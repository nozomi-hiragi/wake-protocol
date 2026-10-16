// Non-negative safe integers (0..2^53-1) to and from the BigInt of a u64 field.
// Used for values carried as u64 on the wire and as I-JSON integers in the API,
// such as times in milliseconds.

/** Safe, non-negative integer to the BigInt to encode as u64. */
export function numberToBigInt(n: number): bigint {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError("must be an integer in 0..2^53-1");
  return BigInt(n);
}

/** A u64 BigInt back to a number; values outside 0..2^53-1 are rejected. */
export function bigIntToNumber(v: bigint): number {
  if (v < 0n || v > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError("must be an integer in 0..2^53-1");
  return Number(v);
}
