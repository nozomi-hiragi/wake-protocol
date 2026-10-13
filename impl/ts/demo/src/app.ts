// Demo server. Passkey registration here is NOT part of WAKE (spec §1); only /auth/* and /wake/* are.
import { readFile } from "node:fs/promises";
import { base64urlnopad } from "@scure/base";
import { Hono } from "hono";
import type { Context } from "hono";
import { bytesToUtf8, parseIJson, utf8ToBytes } from "@wake-protocol/codec";
import { importP256SpkiPublicKey, randomBytes, sha256 } from "@wake-protocol/crypto";
import { createWakeServer, MemoryCredentialStore, MemoryWakeStore } from "@wake-protocol/server";
import type { EtAuth, EtRoute, EtRouteResponse, OperationView, WakeServer } from "@wake-protocol/server";

export interface DemoAppOptions {
  rpId: string;
  origin: string;
  secret?: Uint8Array;
  now?: () => number;
}

export interface DemoApp {
  app: Hono;
  server: WakeServer;
  credentials: MemoryCredentialStore;
  store: MemoryWakeStore;
}

interface PendingRegistration {
  challenge: Uint8Array;
  userId: Uint8Array;
  expiresAt: number;
}

const REGISTRATION_TTL_MS = 300_000;
const MAX_BODY = 65_536;
const CSP = "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
const FILES = new URL("../", import.meta.url);
const OPERATION_LIFETIME_MS = 600_000;
const MAX_ET_BODY = 16_384;
// Demo only: caps the PENDING operations one user can pile up through the demo route.
const MAX_PENDING_OPERATIONS = 20;
const OPERATION_ID = /^[0-9a-f]{64}$/u;

class BadRequest extends Error {}

class Conflict extends Error {}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function field(value: unknown, name: string): Record<string, unknown> {
  if (!isObject(value) || !isObject(value[name])) {
    throw new BadRequest();
  }
  return value[name];
}

function binary(value: unknown): Uint8Array {
  if (typeof value !== "string") {
    throw new BadRequest();
  }
  try {
    return base64urlnopad.decode(value);
  } catch {
    throw new BadRequest();
  }
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

async function readJson(c: Context): Promise<Record<string, unknown>> {
  const raw = new Uint8Array(await c.req.arrayBuffer());
  if (raw.length > MAX_BODY) {
    throw new BadRequest();
  }
  let value: unknown;
  try {
    value = parseIJson(bytesToUtf8(raw));
  } catch (e) {
    if (e instanceof SyntaxError || e instanceof RangeError || e instanceof TypeError) {
      throw new BadRequest();
    }
    throw e;
  }
  if (!isObject(value)) {
    throw new BadRequest();
  }
  return value;
}

function contains(haystack: Uint8Array, needle: number[]): boolean {
  for (let i = 0; i + needle.length <= haystack.length; i++) {
    if (needle.every((byte, j) => haystack[i + j] === byte)) {
      return true;
    }
  }
  return false;
}

// Byte-pattern check, NOT a CBOR parse: the attested COSE_Key must contain the exact encodings of the
// EC2 / ES256 / P-256 parameters and of the x and y coordinates taken from the SPKI.
function coseMatches(cose: Uint8Array, spki: Uint8Array): boolean {
  const point = spki.subarray(spki.length - 65);
  if (point[0] !== 0x04) {
    return false;
  }
  const x = [...point.subarray(1, 33)];
  const y = [...point.subarray(33, 65)];
  return [
    [0x01, 0x02],
    [0x03, 0x26],
    [0x20, 0x01],
    [0x21, 0x58, 0x20, ...x],
    [0x22, 0x58, 0x20, ...y],
  ].every(pattern => contains(cose, pattern));
}

function username(body: Record<string, unknown>): string {
  const name = body.username;
  if (typeof name !== "string" || name.length < 1 || name.length > 64) {
    throw new BadRequest();
  }
  return name;
}

// Minimal WebAuthn registration check: no attestation, no CBOR.
async function verifyRegistration(
  credential: Record<string, unknown>,
  pending: PendingRegistration,
  options: { rpId: string; origin: string },
) {
  const rawId = binary(credential.rawId);
  if (rawId.length < 1 || rawId.length > 1023 || credential.id !== base64urlnopad.encode(rawId) || credential.type !== "public-key") {
    throw new BadRequest();
  }
  const response = field(credential, "response");
  let clientData: unknown;
  try {
    clientData = parseIJson(bytesToUtf8(binary(response.clientDataJSON)));
  } catch (e) {
    if (e instanceof SyntaxError || e instanceof RangeError || e instanceof TypeError) {
      throw new BadRequest();
    }
    throw e;
  }
  if (!isObject(clientData) || clientData.type !== "webauthn.create" || clientData.origin !== options.origin) {
    throw new BadRequest();
  }
  if (typeof clientData.challenge !== "string" || !same(binary(clientData.challenge), pending.challenge)) {
    throw new BadRequest();
  }
  if (clientData.crossOrigin !== undefined && clientData.crossOrigin !== false) {
    throw new BadRequest();
  }
  const authData = binary(response.authenticatorData);
  if (authData.length < 55 || !same(authData.subarray(0, 32), await sha256(utf8ToBytes(options.rpId)))) {
    throw new BadRequest();
  }
  const flags = authData[32]!;
  // UP, UV and AT must be set; BE is read; BS without BE is invalid.
  if ((flags & 0x45) !== 0x45 || ((flags & 0x10) !== 0 && (flags & 0x08) === 0)) {
    throw new BadRequest();
  }
  const signCount = new DataView(authData.buffer, authData.byteOffset).getUint32(33, false);
  const idLength = (authData[53]! << 8) | authData[54]!;
  if (authData.length < 55 + idLength || !same(authData.subarray(55, 55 + idLength), rawId)) {
    throw new BadRequest();
  }
  if (response.publicKeyAlgorithm !== -7) {
    throw new BadRequest();
  }
  const publicKey = binary(response.publicKey);
  try {
    await importP256SpkiPublicKey(publicKey);
  } catch {
    throw new BadRequest();
  }
  if (!coseMatches(authData.subarray(55 + idLength), publicKey)) {
    throw new BadRequest();
  }
  const transports = Array.isArray(response.transports) && response.transports.every(t => typeof t === "string") ?
    response.transports as string[] :
    undefined;
  return { rawId, publicKey, signCount, backupEligible: (flags & 0x08) !== 0, transports };
}

function etJson(status: number, value: unknown): EtRouteResponse {
  return { status, headers: [["content-type", "application/json"]], body: utf8ToBytes(JSON.stringify(value)) };
}

function etError(status: number, code: string): EtRouteResponse {
  return etJson(status, { error: { code } });
}

function errorCode(e: unknown): string | undefined {
  return e instanceof Error && "code" in e && typeof e.code === "string" ? e.code : undefined;
}

// JSON-safe summary of the server's decision record; byte fields are base64url.
function decisionRecord(view: OperationView): Record<string, unknown> | undefined {
  const d = view.decision;
  if (!d) {
    return undefined;
  }
  if (d.kind === "approved") {
    return {
      kind: d.kind,
      decidedAt: d.decidedAt,
      decidedByUserId: d.decidedByUserId,
      decidedByCredentialId: base64urlnopad.encode(d.decidedByCredentialId),
      sessionId: base64urlnopad.encode(d.sessionId),
      approvalId: base64urlnopad.encode(d.approvalId),
      th: d.th ? base64urlnopad.encode(d.th) : null,
    };
  }
  if (d.kind === "rejected") {
    return { kind: d.kind, decidedAt: d.decidedAt, decidedByUserId: d.decidedByUserId };
  }
  return { kind: d.kind, decidedAt: d.decidedAt, decidedBy: d.decidedBy };
}

// Demo ET routes (spec §11.5). They are reachable only inside WAKE-ET; auth comes from the in-process object.
function demoRoutes(getServer: () => WakeServer, store: MemoryWakeStore, now: () => number): EtRoute[] {
  // Per-user tail of the create chain (see POST /api/operations).
  const creatingByUser = new Map<string, Promise<void>>();
  return [
    {
      method: "GET",
      path: "/api/me",
      handler: (_req, auth: EtAuth) => etJson(200, {
        userId: auth.userId,
        sessionId: auth.sessionId,
        epoch: auth.epoch,
        authTime: auth.authTime,
      }),
    },
    {
      method: "POST",
      path: "/api/operations",
      async handler(req, auth) {
        if (req.body.length > MAX_ET_BODY) {
          return etError(413, "too_large");
        }
        let content: unknown;
        try {
          const value = parseIJson(bytesToUtf8(req.body));
          content = isObject(value) ? value.content : undefined;
        } catch (e) {
          if (e instanceof SyntaxError || e instanceof RangeError || e instanceof TypeError) {
            return etError(400, "invalid_request");
          }
          throw e;
        }
        if (typeof content !== "string") {
          return etError(400, "invalid_request");
        }
        // The cap check and the create must be atomic per user, or parallel requests could all pass the check.
        // Creates of one user are chained on a promise so each sees the previous one's result.
        const previous = creatingByUser.get(auth.userId) ?? Promise.resolve();
        const run = previous.then(async (): Promise<EtRouteResponse> => {
          const pending = await store.listOperations({
            approverUserId: auth.userId,
            status: "PENDING",
            limit: MAX_PENDING_OPERATIONS,
            now: now(),
          });
          if (pending.length >= MAX_PENDING_OPERATIONS) {
            return etError(409, "too_many_pending");
          }
          try {
            // Demo only: the user requests approval of their own operation. A real app decides content and approver.
            const created = await getServer().createOperation({
              content,
              approverUserId: auth.userId,
              expiresAt: now() + OPERATION_LIFETIME_MS,
            });
            return etJson(200, { operationId: created.operationId, approveUrl: `/approve/${created.operationId}` });
          } catch (e) {
            const code = errorCode(e);
            if (code === "invalid_content" || code === "invalid_request") {
              return etError(400, code);
            }
            throw e;
          }
        });
        // The chain itself never rejects, so one failed request does not poison the next.
        const tail = run.then(() => undefined, () => undefined);
        creatingByUser.set(auth.userId, tail);
        void tail.then(() => {
          if (creatingByUser.get(auth.userId) === tail) {
            creatingByUser.delete(auth.userId);
          }
        });
        return run;
      },
    },
    {
      method: "GET",
      path: "/api/operation",
      async handler(req, auth) {
        const id = new URLSearchParams(req.query).get("id");
        if (id === null || !OPERATION_ID.test(id)) {
          return etError(400, "invalid_request");
        }
        const view = await getServer().getOperation(id);
        // Another user's operation looks exactly like an unknown one.
        if (!view || view.approverUserId !== auth.userId) {
          return etError(404, "not_found");
        }
        const record = decisionRecord(view);
        return etJson(200, {
          status: view.status,
          decidedAt: view.decidedAt,
          ...(record ? { decisionRecord: record } : {}),
        });
      },
    },
  ];
}

async function file(path: string, type: string): Promise<Response> {
  try {
    const body = await readFile(new URL(path, FILES));
    return new Response(new Uint8Array(body), { headers: { "content-type": type, "cache-control": "no-store" } });
  } catch {
    return new Response("not found", { status: 404 });
  }
}

export function createDemoApp(options: DemoAppOptions): DemoApp {
  const now = options.now ?? Date.now;
  const credentials = new MemoryCredentialStore();
  const store = new MemoryWakeStore();
  const server: WakeServer = createWakeServer({
    rpId: options.rpId,
    loginOrigins: [options.origin],
    secret: options.secret ?? randomBytes(32),
    credentials,
    store,
    now,
    routes: demoRoutes(() => server, store, now),
  });
  const pending = new Map<string, PendingRegistration>();
  const app = new Hono();
  const host = new URL(options.origin).host;

  app.use("*", async (c, next) => {
    if (new URL(c.req.url).host !== host) {
      return c.json({ error: "bad_host" }, 421, { "Content-Security-Policy": CSP });
    }
    await next();
    c.res.headers.set("Content-Security-Policy", CSP);
  });

  app.onError((e, c) => {
    if (e instanceof BadRequest) {
      return c.json({ error: "bad_request" }, 400);
    }
    if (e instanceof Conflict) {
      return c.json({ error: e.message }, 409);
    }
    return c.json({ error: "internal" }, 500);
  });

  app.all("/auth/*", async c => (await server.handle(c.req.raw)) ?? c.notFound());
  app.all("/wake/*", async c => (await server.handle(c.req.raw)) ?? c.notFound());

  app.post("/register/options", async c => {
    const name = username(await readJson(c));
    if (await credentials.findUserByUsername(name)) {
      return c.json({ error: "username_taken" }, 409);
    }
    for (const [key, entry] of pending) {
      if (now() >= entry.expiresAt) {
        pending.delete(key);
      }
    }
    if (pending.has(name)) {
      return c.json({ error: "registration_pending" }, 409);
    }
    const challenge = randomBytes(32);
    const userId = randomBytes(16);
    pending.set(name, { challenge, userId, expiresAt: now() + REGISTRATION_TTL_MS });
    return c.json({
      challenge: base64urlnopad.encode(challenge),
      rp: { id: options.rpId, name: "WAKE demo" },
      user: { id: base64urlnopad.encode(userId), name, displayName: name },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      attestation: "none",
      timeout: 60_000,
    });
  });

  app.post("/register/verify", async c => {
    const body = await readJson(c);
    const name = username(body);
    const entry = pending.get(name);
    // The challenge is single use, even when verification fails.
    pending.delete(name);
    if (!entry || now() >= entry.expiresAt) {
      throw new BadRequest();
    }
    if (await credentials.findUserByUsername(name)) {
      return c.json({ error: "username_taken" }, 409);
    }
    const verified = await verifyRegistration(field(body, "credential"), entry, options);
    if (await credentials.getCredential(verified.rawId)) {
      throw new Conflict("credential_exists");
    }
    try {
      credentials.setCredential({
        credentialId: verified.rawId,
        userId: base64urlnopad.encode(entry.userId),
        userHandle: entry.userId,
        publicKey: verified.publicKey,
        algorithm: -7,
        signCount: verified.signCount,
        backupEligible: verified.backupEligible,
        status: "active",
        ...(verified.transports ? { transports: verified.transports } : {}),
      }, name);
    } catch {
      // The store refuses to re-bind a credential id or username to another user.
      throw new Conflict("credential_exists");
    }
    return c.json({ ok: true });
  });

  app.get("/", () => file("public/index.html", "text/html; charset=utf-8"));
  app.get("/app.css", () => file("public/app.css", "text/css; charset=utf-8"));
  app.get("/app.js", () => file("dist/app.js", "text/javascript; charset=utf-8"));
  app.get("/approve.js", () => file("dist/approve.js", "text/javascript; charset=utf-8"));
  app.get("/approve/:operationId", (c) => {
    if (!OPERATION_ID.test(c.req.param("operationId"))) {
      return c.notFound();
    }
    return file("public/approve.html", "text/html; charset=utf-8");
  });

  return { app, server, credentials, store };
}
