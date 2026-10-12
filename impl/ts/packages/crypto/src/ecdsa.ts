// Generic ECDSA signature encoding and P-256 verification helpers.

const subtle = globalThis.crypto.subtle;

/** Converts a strict DER ECDSA signature into fixed-width IEEE-P1363 form. */
export function ecdsaDerToRaw(der: Uint8Array, size: number): Uint8Array {
  if (!Number.isSafeInteger(size) || size <= 0) {
    throw new RangeError("size must be a positive safe integer");
  }
  if (!(der instanceof Uint8Array)) {
    throw new TypeError("DER signature must be a Uint8Array");
  }

  let offset = 0;
  const readLength = (): number => {
    const length = der[offset++];
    if (length === undefined || (length & 0x80) !== 0) {
      throw new RangeError("DER lengths must use short form");
    }
    return length;
  };

  if (der[offset++] !== 0x30) {
    throw new RangeError("DER signature must be a SEQUENCE");
  }
  const sequenceLength = readLength();
  if (offset + sequenceLength !== der.length) {
    throw new RangeError("DER sequence length mismatch or trailing data");
  }

  const readInteger = (): Uint8Array => {
    if (der[offset++] !== 0x02) {
      throw new RangeError("DER signature members must be INTEGERs");
    }
    const length = readLength();
    if (length === 0) {
      throw new RangeError("DER INTEGER must not be empty");
    }
    const end = offset + length;
    if (end > der.length) {
      throw new RangeError("DER INTEGER length mismatch");
    }
    let value = der.subarray(offset, end);
    offset = end;
    if ((value[0]! & 0x80) !== 0) {
      throw new RangeError("DER INTEGER must be positive");
    }
    if (value.length > 1 && value[0] === 0) {
      if ((value[1]! & 0x80) === 0) {
        throw new RangeError("DER INTEGER is not minimally encoded");
      }
      value = value.subarray(1);
    }
    if (value.length > size) {
      throw new RangeError("DER INTEGER exceeds requested width");
    }
    let nonzero = false;
    for (const byte of value) {
      nonzero ||= byte !== 0;
    }
    if (!nonzero) {
      throw new RangeError("DER INTEGER must be nonzero");
    }
    return value;
  };

  const r = readInteger();
  const s = readInteger();
  if (offset !== der.length) throw new RangeError("trailing data inside DER sequence");

  const raw = new Uint8Array(size * 2);
  raw.set(r, size - r.length);
  raw.set(s, size * 2 - s.length);
  return raw;
}

/** Converts fixed-width IEEE-P1363 form into a minimal DER ECDSA signature. */
export function ecdsaRawToDer(raw: Uint8Array): Uint8Array {
  if (!(raw instanceof Uint8Array)) {
    throw new TypeError("raw signature must be a Uint8Array");
  }
  if (raw.length === 0 || raw.length % 2 !== 0) {
    throw new RangeError("raw signature must contain two equal-width integers");
  }
  const size = raw.length / 2;

  const encodeInteger = (input: Uint8Array): Uint8Array => {
    let first = 0;
    while (first < input.length && input[first] === 0) {
      first++;
    }
    if (first === input.length) {
      throw new RangeError("ECDSA integers must be nonzero");
    }
    const value = input.subarray(first);
    const needsSignByte = (value[0]! & 0x80) !== 0;
    const encoded = new Uint8Array(2 + value.length + (needsSignByte ? 1 : 0));
    encoded[0] = 0x02;
    encoded[1] = value.length + (needsSignByte ? 1 : 0);
    encoded.set(
      value,
      2 + (needsSignByte ? 1 : 0),
    );
    return encoded;
  };

  const r = encodeInteger(raw.subarray(0, size));
  const s = encodeInteger(raw.subarray(size));
  const contentLength = r.length + s.length;
  if (contentLength >= 0x80) {
    throw new RangeError("signature is too large for short-form DER");
  }
  const der = new Uint8Array(2 + contentLength);
  der[0] = 0x30;
  der[1] = contentLength;
  der.set(r, 2);
  der.set(s, 2 + r.length);
  return der;
}

/** Imports an SPKI P-256 ECDSA public key for verification only. */
export async function importP256SpkiPublicKey(spki: Uint8Array): Promise<CryptoKey> {
  if (!(spki instanceof Uint8Array)) {
    throw new TypeError("SPKI must be a Uint8Array");
  }
  return subtle.importKey(
    "spki",
    new Uint8Array(spki),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
}

/** Verifies a 64-byte IEEE-P1363 signature over data with ECDSA/SHA-256. */
export async function p256EcdsaVerify(key: CryptoKey, rawSignature: Uint8Array, data: Uint8Array): Promise<boolean> {
  if (!(rawSignature instanceof Uint8Array) || !(data instanceof Uint8Array)) {
    throw new TypeError("signature and data must be Uint8Arrays");
  }
  if (rawSignature.length !== 64) {
    throw new RangeError("P-256 signature must be 64 bytes");
  }
  return subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new Uint8Array(rawSignature),
    new Uint8Array(data),
  );
}
