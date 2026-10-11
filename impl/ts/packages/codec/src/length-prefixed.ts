// Fields each prefixed with a 4-byte big-endian length, and strict decoding.

export function encodeU32LengthPrefixed(...fields: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const f of fields) {
    if (f.length > 0xffffffff) throw new RangeError("u32 out of range");
    length += 4 + f.length;
  }
  const out = new Uint8Array(length);
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const f of fields) {
    view.setUint32(offset, f.length);
    out.set(f, offset + 4);
    offset += 4 + f.length;
  }
  return out;
}

/** Splits a sequence of length-prefixed fields. Structured inputs must also pass checkFieldLengths. */
export function decodeU32LengthPrefixed(input: Uint8Array): Uint8Array[] {
  const buf = input;
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const out: Uint8Array[] = [];
  let o = 0;
  while (o < buf.length) {
    if (o + 4 > buf.length) throw new RangeError("truncated length prefix");
    const start = o + 4;
    const end = start + view.getUint32(o);
    if (end > buf.length) throw new RangeError("truncated field");
    out.push(new Uint8Array(buf.subarray(start, end)));
    o = end;
  }
  return out;
}

/**
 * Strict-decoding check: `lengths` fixes the field count; a number
 * entry requires that exact length, `null` allows any length. Returns `fields`.
 */
export function checkFieldLengths(fields: Uint8Array[], lengths: readonly (number | null)[]): Uint8Array[] {
  if (fields.length !== lengths.length) throw new RangeError(`field count ${fields.length}, want ${lengths.length}`);
  lengths.forEach((want, i) => {
    const len = fields[i]!.length;
    if (want !== null && len !== want) throw new RangeError(`field length ${len}, want ${want}`);
  });
  return fields;
}

