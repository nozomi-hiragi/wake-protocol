// Times are milliseconds since the Unix epoch, carried as u64 on the wire
// (§8.2, §5.7) and as I-JSON safe integers in the API (§4.8).
import { fail } from "./errors.ts";

/** ms (safe, non-negative integer) to the u64 value to encode. */
export function timeToU64(ms: number): bigint {
  if (!Number.isSafeInteger(ms) || ms < 0) fail("bad_request", "time must be an integer in 0..2^53-1");
  return BigInt(ms);
}

/** A decoded u64 time back to ms; values above 2^53-1 are rejected. */
export function u64ToTime(v: bigint): number {
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) fail("bad_request", "time exceeds 2^53-1");
  return Number(v);
}
