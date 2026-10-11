// Demo server. Passkey registration here is NOT part of WAKE (spec §1); only /auth/* and /wake/* are.
import { readFile } from "node:fs/promises";
import { base64urlnopad } from "@scure/base";
import { Hono } from "hono";
import type { Context } from "hono";
import { bytesToUtf8, parseIJson, utf8ToBytes } from "@wake-protocol/codec";
import { importP256SpkiPublicKey, randomBytes, sha256 } from "@wake-protocol/crypto";
import { createWakeServer, MemoryCredentialStore, MemoryWakeStore } from "@wake-protocol/server";
import type { WakeServer } from "@wake-protocol/server";

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
  const server = createWakeServer({
    rpId: options.rpId,
    loginOrigins: [options.origin],
    secret: options.secret ?? randomBytes(32),
    credentials,
    store,
    now,
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

  return { app, server, credentials, store };
}
