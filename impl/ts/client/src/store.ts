// Spec §8.7, §8.11, §9.6, §9.7: pluggable session record shared across tabs.
import { WakeError } from "@wake-protocol/core";
import type { C2sCryptoKey, S2cCryptoKey } from "@wake-protocol/core";

export interface StoredEpoch {
  epoch: number;
  /** extractable: false. Structured-cloneable; not a Bytes (private fields are dropped). */
  c2s: C2sCryptoKey;
  s2c: S2cCryptoKey;
  /** Raw 32-byte transcript hash. */
  th: Uint8Array;
}

export interface StoredSession {
  /** Normalized client baseUrl (§8.11 established_origin). Records for another baseUrl are ignored. */
  baseUrl: string;
  /** base64url, no padding. */
  sessionId: string;
  current: StoredEpoch;
  /** Present only between sending kr/complete (or TA+KR approve) and commit or discard. */
  pending?: StoredEpoch;
  offset: number;
  absoluteExpiresAt: number;
  idleTimeoutSec: number;
}

export interface StoreExpectation {
  sessionId: string;
  epoch?: number;
}

export interface SessionStore {
  load(): Promise<StoredSession | undefined>;
  /** Replaces the record. With `expect`, writes only when the stored record matches. */
  save(record: StoredSession, expect?: StoreExpectation): Promise<boolean>;
  /** Deletes the record and its counters. With `expect`, deletes only when the record matches. */
  clear(expect?: StoreExpectation): Promise<boolean>;
  /**
   * Atomically reserves up to `count` encryptions for (sessionId, epoch) under `limit` (§8.7).
   * Returns how many were granted. Zero means the limit is already reached.
   */
  reserveEncryptions(sessionId: string, epoch: number, count: number, limit: number): Promise<number>;
  /** Runs `fn` under an exclusive lock. If the name is held elsewhere, rejects with conflict without waiting. */
  lock<T>(name: string, fn: () => Promise<T>): Promise<T>;
  /** Calls `listener` after every successful save or clear from any context. Returns unsubscribe. */
  subscribe(listener: () => void): () => void;
}

function matches(record: StoredSession | undefined, expect: StoreExpectation | undefined): boolean {
  if (expect === undefined) {
    return true;
  }
  if (record === undefined || record.sessionId !== expect.sessionId) {
    return false;
  }
  return expect.epoch === undefined || record.current.epoch === expect.epoch;
}

function counterKey(sessionId: string, epoch: number): string {
  return `${sessionId}:${epoch}`;
}

function grant(used: number, count: number, limit: number): number {
  if (count <= 0 || used >= limit) {
    return 0;
  }
  return Math.min(count, limit - used);
}

function createHub(): { notify: () => void; subscribe: SessionStore["subscribe"] } {
  const listeners = new Set<() => void>();
  return {
    // After the write, before the caller's await continues (queueMicrotask runs first).
    notify() {
      queueMicrotask(() => {
        for (const listener of [...listeners]) listener();
      });
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
  };
}

function inProcessLock(): SessionStore["lock"] {
  const held = new Set<string>();
  return async (name, fn) => {
    if (held.has(name)) {
      throw new WakeError("conflict");
    }
    held.add(name);
    try {
      return await fn();
    } finally {
      held.delete(name);
    }
  };
}

/** Per-instance store. Clones on save and load so tests catch values that do not survive structured clone. */
export function memorySessionStore(): SessionStore {
  let record: StoredSession | undefined;
  const counters = new Map<string, number>();
  const hub = createHub();
  const lock = inProcessLock();
  return {
    async load() {
      return record === undefined ? undefined : structuredClone(record);
    },
    async save(next, expect) {
      if (!matches(record, expect)) {
        return false;
      }
      if (record !== undefined && record.sessionId !== next.sessionId) {
        counters.clear();
      }
      record = structuredClone(next);
      hub.notify();
      return true;
    },
    async clear(expect) {
      if (!matches(record, expect)) {
        return false;
      }
      record = undefined;
      counters.clear();
      hub.notify();
      return true;
    },
    async reserveEncryptions(sessionId, epoch, count, limit) {
      const key = counterKey(sessionId, epoch);
      const used = counters.get(key) ?? 0;
      const granted = grant(used, count, limit);
      if (granted > 0) {
        counters.set(key, used + granted);
      }
      return granted;
    },
    lock,
    subscribe: (listener) => hub.subscribe(listener),
  };
}

function openDatabase(name: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = globalThis.indexedDB.open(name, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("session")) {
        db.createObjectStore("session");
      }
      if (!db.objectStoreNames.contains("counters")) {
        db.createObjectStore("counters");
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("indexedDB open failed"));
  });
}

function transactionDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(tx.error ?? new Error("indexedDB transaction aborted"));
  });
}

async function finish<T>(tx: IDBTransaction, work: Promise<T>): Promise<T> {
  const done = transactionDone(tx);
  try {
    const result = await work;
    await done;
    return result;
  } catch (error) {
    await done.then(() => undefined, () => undefined);
    throw error;
  }
}

const SESSION_KEY = "current";

function readCurrent(
  store: IDBObjectStore,
  then: (record: StoredSession | undefined) => void,
  reject: (error: unknown) => void,
): void {
  const request = store.get(SESSION_KEY);
  request.onsuccess = () => then(request.result as StoredSession | undefined);
  request.onerror = () => reject(request.error ?? new Error("indexedDB get failed"));
}

/** IndexedDB when available; otherwise an in-memory store (a reload then needs a new login, §8.11). */
export function indexedDbSessionStore(options?: { name?: string }): SessionStore {
  const name = options?.name ?? "wake-protocol";
  const fallback = memorySessionStore();
  const localLock = inProcessLock();
  const hub = createHub();
  let opening: Promise<IDBDatabase | undefined> | undefined;
  let channel: BroadcastChannel | undefined;

  const database = (): Promise<IDBDatabase | undefined> => {
    if (opening === undefined) {
      opening = (async () => {
        if (globalThis.indexedDB === undefined) {
          return undefined;
        }
        try {
          const db = await openDatabase(name);
          channel = new BroadcastChannel(name);
          channel.onmessage = (event) => {
            if (event.data === "changed") {
              hub.notify();
            }
          };
          return db;
        } catch {
          return undefined;
        }
      })();
    }
    return opening;
  };

  const notify = () => {
    hub.notify();
    channel?.postMessage("changed");
  };

  return {
    async load() {
      const db = await database();
      if (db === undefined) {
        return fallback.load();
      }
      const tx = db.transaction("session", "readonly");
      return finish(tx, new Promise<StoredSession | undefined>((resolve, reject) => {
        readCurrent(tx.objectStore("session"), resolve, reject);
      }));
    },
    async save(next, expect) {
      const db = await database();
      if (db === undefined) {
        const wrote = await fallback.save(next, expect);
        if (wrote) {
          hub.notify();
        }
        return wrote;
      }
      const tx = db.transaction(["session", "counters"], "readwrite");
      const wrote = await finish(tx, new Promise<boolean>((resolve, reject) => {
        const sessions = tx.objectStore("session");
        readCurrent(sessions, (existing) => {
          if (!matches(existing, expect)) {
            resolve(false);
            return;
          }
          if (existing !== undefined && existing.sessionId !== next.sessionId) {
            tx.objectStore("counters").clear();
          }
          const put = sessions.put(next, SESSION_KEY);
          put.onsuccess = () => resolve(true);
          put.onerror = () => reject(put.error ?? new Error("indexedDB put failed"));
        }, reject);
      }));
      if (wrote) {
        notify();
      }
      return wrote;
    },
    async clear(expect) {
      const db = await database();
      if (db === undefined) {
        const wrote = await fallback.clear(expect);
        if (wrote) {
          hub.notify();
        }
        return wrote;
      }
      const tx = db.transaction(["session", "counters"], "readwrite");
      const wrote = await finish(tx, new Promise<boolean>((resolve, reject) => {
        const sessions = tx.objectStore("session");
        readCurrent(sessions, (existing) => {
          if (!matches(existing, expect)) {
            resolve(false);
            return;
          }
          sessions.delete(SESSION_KEY);
          tx.objectStore("counters").clear();
          resolve(true);
        }, reject);
      }));
      if (wrote) {
        notify();
      }
      return wrote;
    },
    async reserveEncryptions(sessionId, epoch, count, limit) {
      const db = await database();
      if (db === undefined) {
        return fallback.reserveEncryptions(sessionId, epoch, count, limit);
      }
      const tx = db.transaction("counters", "readwrite");
      return finish(tx, new Promise<number>((resolve, reject) => {
        const counters = tx.objectStore("counters");
        const key = counterKey(sessionId, epoch);
        const request = counters.get(key);
        request.onsuccess = () => {
          const used = typeof request.result === "number" ? request.result : 0;
          const n = grant(used, count, limit);
          if (n === 0) {
            resolve(0);
            return;
          }
          const put = counters.put(used + n, key);
          put.onsuccess = () => resolve(n);
          put.onerror = () => reject(put.error ?? new Error("indexedDB put failed"));
        };
        request.onerror = () => reject(request.error ?? new Error("indexedDB get failed"));
      }));
    },
    async lock(lockName, fn) {
      const webLocks = globalThis.navigator?.locks;
      if (webLocks === undefined) {
        return localLock(lockName, fn);
      }
      return webLocks.request(lockName, { ifAvailable: true }, async (held) => {
        if (held === null) {
          throw new WakeError("conflict");
        }
        return await fn();
      });
    },
    subscribe: (listener) => hub.subscribe(listener),
  };
}
