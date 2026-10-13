// Nominal typing for byte strings. Branded types are erased at runtime.
import { Bytes } from "./bytes.ts";

export type Brand<B extends string> = Bytes & { readonly __brand: B };

/** Factory that length-checks bytes and brands them. Throws RangeError on a wrong length. */
export function fixedLength<B extends string>(name: string, len: number): (b: Bytes | Uint8Array) => Brand<B> {
  return (b) => {
    if (b.length !== len) throw new RangeError(`${name} must be ${len} bytes`);
    return (b instanceof Bytes ? b : new Bytes(b)) as Brand<B>;
  };
}
