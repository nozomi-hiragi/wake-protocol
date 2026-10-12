// Spec §8.3–§8.9, §12.3–§12.4: ordered authenticated message dispatch.
import { Bytes, DIR_C2S, DIR_S2C, openParsed, parseJsonObject, parseWire, seal, WakeError } from "@wake-protocol/core";
import type { MsgHeader, ParsedWire } from "@wake-protocol/core";
import { utf8ToBytes } from "@wake-protocol/codec";
import { checkContentType, outerError, readBody } from "../http.ts";
import type { ServerOptions } from "../options.ts";
import type { EpochKeys, SessionRecord } from "../store/types.ts";
import { sessionExpired } from "./lifetime.ts";
import { sessionInfo } from "./session.ts";

interface DispatchResult {
  body: unknown;
  logout: boolean;
}

function selectKeys(session: SessionRecord, epoch: number, now: number): EpochKeys {
  if (epoch > session.currentEpoch) {
    throw new WakeError("reauth");
  }
  if (epoch === session.currentEpoch) {
    if (!session.currentKeys) {
      throw new WakeError("reauth");
    }
    return session.currentKeys;
  }
  if (epoch === session.currentEpoch - 1 && now <= (session.prevValidUntil ?? -1) && session.prevKeys) {
    return session.prevKeys;
  }
  throw new WakeError("epoch_retired");
}

function encryptedError(code: string): { error: { code: string } } {
  return { error: { code } };
}

async function parseRequest(req: Request, options: ServerOptions): Promise<ParsedWire> {
  checkContentType(req, "application/wake");
  const body = await readBody(req, 4 + 371 + options.maxPlaintext + 16, "too_large");
  const parsed = parseWire(body, { maxPlaintext: options.maxPlaintext });
  if (parsed.header.dir !== DIR_C2S) {
    throw new WakeError("bad_request");
  }
  return parsed;
}

async function findKeys(header: MsgHeader, options: ServerOptions): Promise<EpochKeys> {
  const sessionId = header.sessionId.toUint8Array();
  const session = await options.store.getSession(sessionId);
  const now = options.now();
  if (!session || session.status !== "ACTIVE") {
    throw new WakeError("reauth");
  }
  if (sessionExpired(session, now)) {
    await options.store.expireSession(sessionId, now);
    throw new WakeError("reauth");
  }
  return selectKeys(session, header.epoch, now);
}

async function reserveEncryptions(header: MsgHeader, options: ServerOptions): Promise<Response | null> {
  const sessionId = header.sessionId.toUint8Array();
  // Atomic reservation includes the reply even for encrypted errors and replays.
  // Conservative accounting burns the reservation if sealing subsequently fails.
  let reserved: boolean;
  try {
    reserved = await options.store.reserveEncryptions(
      sessionId,
      header.epoch,
      options.now(),
      options.maxEncryptionsPerKey,
    );
  } catch (e) {
    // Fail closed: no encrypted response without guaranteed §8.7 accounting.
    const limited = e instanceof WakeError && e.code === "rate_limited";
    return outerError(limited ? "rate_limited" : "retry", options.retryAfterSec);
  }
  if (!reserved) {
    await options.store.expireSession(sessionId, options.now());
    return outerError("reauth", options.retryAfterSec);
  }
  return null;
}

async function dispatchSession(header: MsgHeader, options: ServerOptions): Promise<DispatchResult | Response> {
  const sessionId = header.sessionId.toUint8Array();
  if (header.context === "wake/session") {
    const latest = await options.store.getSession(sessionId);
    if (!latest || latest.status !== "ACTIVE") {
      return outerError("reauth", options.retryAfterSec);
    }
    if (sessionExpired(latest, options.now())) {
      await options.store.expireSession(sessionId, options.now());
      return outerError("reauth", options.retryAfterSec);
    }
    return { body: sessionInfo(latest, options.now()), logout: false };
  }
  const revoked = await options.store.revokeForLogout(sessionId, options.now());
  if (!revoked) {
    await options.store.expireSession(sessionId, options.now());
    return outerError("reauth", options.retryAfterSec);
  }
  return { body: {}, logout: true };
}

async function dispatch(
  header: MsgHeader,
  plaintext: Bytes,
  options: ServerOptions,
): Promise<DispatchResult | Response> {
  try {
    const now = options.now();
    if (Math.abs(now - header.issuedAt) > options.freshnessWindowMs) {
      return { body: encryptedError("stale_request"), logout: false };
    }
    // §8.5: stale requests cannot extend the idle timeout.
    await options.store.touchSession(header.sessionId.toUint8Array(), now);
    if (header.context !== "wake/session" && header.context !== "wake/logout") {
      return { body: encryptedError("invalid_context"), logout: false };
    }
    parseJsonObject(plaintext.toUint8Array(), "invalid_request");
    return await dispatchSession(header, options);
  } catch (e) {
    const code = e instanceof WakeError && (e.code === "invalid_request" || e.code === "rate_limited") ? e.code : "internal";
    return { body: encryptedError(code), logout: false };
  }
}

async function sealResponse(
  header: MsgHeader,
  keys: EpochKeys,
  result: DispatchResult,
  options: ServerOptions,
): Promise<Response> {
  try {
    const wire = await seal(
      keys.s2c,
      {
        dir: DIR_S2C,
        sessionId: header.sessionId,
        epoch: header.epoch,
        requestId: header.requestId,
        context: header.context,
        issuedAt: options.now(),
      },
      new Bytes(utf8ToBytes(JSON.stringify(result.body))),
      { maxPlaintext: options.maxPlaintext },
    );
    return new Response(wire.toUint8Array(), {
      status: 200,
      headers: { "content-type": "application/wake" },
    });
  } finally {
    if (result.logout) {
      await options.store.deleteSessionKeys(header.sessionId.toUint8Array());
    }
  }
}

export async function up(req: Request, options: ServerOptions): Promise<Response> {
  const parsed = await parseRequest(req, options);
  const keys = await findKeys(parsed.header, options);
  const plaintext = await openParsed(keys.c2s, parsed, DIR_C2S);
  const reservationError = await reserveEncryptions(parsed.header, options);
  if (reservationError) {
    return reservationError;
  }
  const result = await dispatch(parsed.header, plaintext, options);
  if (result instanceof Response) {
    return result;
  }
  return sealResponse(parsed.header, keys, result, options);
}
