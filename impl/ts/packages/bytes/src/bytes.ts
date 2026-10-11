// Immutable byte strings and fixed-width big-endian integers.

/**
 * Immutable-by-ownership byte value. Input and output arrays are copied.
 * Copies prevent reliable secret erasure; this is not a secure-memory container.
 */
export class Bytes implements Iterable<number> {
  readonly #data: Uint8Array<ArrayBuffer>;

  /** Array elements use Uint8Array coercion: [256, -1, 1.5] becomes [0, 255, 1]. */
  constructor(data: Bytes | ArrayLike<number>) {
    this.#data = data instanceof Bytes ? data.toUint8Array() : new Uint8Array(data);
  }

  get length(): number {
    return this.#data.length;
  }

  at(index: number): number | undefined {
    return this.#data.at(index);
  }

  slice(start?: number, end?: number): Bytes {
    return new Bytes(this.#data.slice(start, end));
  }

  toUint8Array(): Uint8Array<ArrayBuffer> {
    return this.#data.slice();
  }

  equals(other: Bytes): boolean {
    if (this.length !== other.length) return false;
    for (let i = 0; i < this.length; i++) if (this.#data[i] !== other.#data[i]) return false;
    return true;
  }

  static concat(...parts: Bytes[]): Bytes {
    let n = 0;
    for (const p of parts) n += p.length;
    const out = new Uint8Array(n);
    let o = 0;
    for (const p of parts) {
      out.set(p.#data, o);
      o += p.length;
    }
    return new Bytes(out);
  }

  [Symbol.iterator](): IterableIterator<number> {
    return this.#data[Symbol.iterator]();
  }
}

/** One unsigned byte. */
export class Byte extends Bytes {
  constructor(value: number | Bytes = 0) {
    super(Byte.#encode(value));
  }

  static #encode(value: number | Bytes): Bytes | Uint8Array {
    if (value instanceof Bytes) {
      if (value.length !== 1) throw new RangeError("u8 length");
      return value;
    }
    if (!Number.isInteger(value) || value < 0 || value > 0xff) throw new RangeError("u8 out of range");
    return Uint8Array.of(value);
  }

  get number(): number {
    return this.at(0)!;
  }
}

/** Unsigned 16-bit big-endian value. */
export class Byte2 extends Bytes {
  constructor(value: number | Bytes = 0) {
    super(Byte2.#encode(value));
  }

  static #encode(value: number | Bytes): Bytes | Uint8Array {
    if (value instanceof Bytes) {
      if (value.length !== 2) throw new RangeError("u16 length");
      return value;
    }
    if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw new RangeError("u16 out of range");
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, value);
    return b;
  }

  get number(): number {
    return this.at(0)! * 0x100 + this.at(1)!;
  }
}

/** Unsigned 32-bit big-endian value. */
export class Byte4 extends Bytes {
  constructor(value: number | Bytes = 0) {
    super(Byte4.#encode(value));
  }

  static #encode(value: number | Bytes): Bytes | Uint8Array {
    if (value instanceof Bytes) {
      if (value.length !== 4) throw new RangeError("u32 length");
      return value;
    }
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new RangeError("u32 out of range");
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, value);
    return b;
  }

  get number(): number {
    return this.at(0)! * 0x1000000 + (this.at(1)! << 16) + (this.at(2)! << 8) + this.at(3)!;
  }
}

/** Unsigned 64-bit big-endian value. */
export class Byte8 extends Bytes {
  constructor(value: bigint | Bytes = 0n) {
    super(Byte8.#encode(value));
  }

  static #encode(value: bigint | Bytes): Bytes | Uint8Array {
    if (value instanceof Bytes) {
      if (value.length !== 8) throw new RangeError("u64 length");
      return value;
    }
    if (typeof value !== "bigint") throw new TypeError("u64 must be a bigint");
    if (value < 0n || value > 0xffffffffffffffffn) throw new RangeError("u64 out of range");
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, value);
    return b;
  }

  get number(): bigint {
    return new DataView(this.toUint8Array().buffer).getBigUint64(0);
  }
}

export const EMPTY = new Bytes(new Uint8Array(0));
