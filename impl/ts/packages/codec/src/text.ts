// Strict text codecs: ASCII, UTF-8 and Latin-1 to and from bytes.
const strictDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Throws RangeError on a non-ASCII character. */
export function asciiToBytes(s: string): Uint8Array {
  const b = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0x7f) throw new RangeError("non-ASCII character");
    b[i] = c;
  }
  return b;
}

/** Throws RangeError on a non-ASCII byte. */
export function bytesToAscii(b: Uint8Array): string {
  let s = "";
  for (const c of b) {
    if (c > 0x7f) throw new RangeError("non-ASCII byte");
    s += String.fromCharCode(c);
  }
  return s;
}

/** Throws TypeError on a lone surrogate. */
export function utf8ToBytes(s: string): Uint8Array {
  if (!s.isWellFormed()) throw new TypeError("lone surrogate");
  return new TextEncoder().encode(s);
}

/** Throws TypeError on invalid UTF-8. */
export function bytesToUtf8(b: Uint8Array): string {
  return strictDecoder.decode(b);
}

/** One byte per char. Throws RangeError on a char above U+00FF. */
export function latin1ToBytes(s: string): Uint8Array {
  const b = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0xff) throw new RangeError("character above U+00FF");
    b[i] = c;
  }
  return b;
}

/** One char per byte. */
export function bytesToLatin1(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return s;
}
