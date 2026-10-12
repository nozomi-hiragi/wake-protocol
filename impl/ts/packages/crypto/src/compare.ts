// Generic byte-array comparison helpers.
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let difference = 0;
  for (let i = 0; i < a.length; i += 1) {
    difference |= a[i]! ^ b[i]!;
  }
  return difference === 0;
}
