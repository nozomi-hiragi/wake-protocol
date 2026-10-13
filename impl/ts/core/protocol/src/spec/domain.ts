// LP input that starts with a domain-separation label (spec §4.2, §5).
import { Bytes } from "@wake-protocol/bytes";
import { asciiToBytes, checkFieldLengths, encodeU32LengthPrefixed, decodeU32LengthPrefixed } from "@wake-protocol/codec";
import { fail } from "./errors.ts";

export function labeled(label: string, ...fields: (Bytes | Uint8Array)[]): Bytes {
  return encodeFields(asciiToBytes(label), ...fields);
}

export function encodeFields(...fields: (Bytes | Uint8Array)[]): Bytes {
  return new Bytes(encodeU32LengthPrefixed(...fields.map((f) => f instanceof Bytes ? f.toUint8Array() : f)));
}

export function decodeFields(input: Bytes | Uint8Array, lengths?: readonly (number | null)[]): Bytes[] {
  const fields = decodeU32LengthPrefixed(input instanceof Bytes ? input.toUint8Array() : input);
  return (lengths ? checkFieldLengths(fields, lengths) : fields).map((f) => new Bytes(f));
}

/** Fails with `code` unless `field` is exactly the ASCII bytes of `label`. */
export function expectLabel(field: Bytes, label: string, code: string): void {
  if (!field.equals(new Bytes(asciiToBytes(label)))) fail(code, "label");
}
