// Spec §6.1: browser assertion options and JSON conversion.
import assert from "node:assert/strict";
import { test } from "node:test";
import { navigatorGetAssertion } from "../src/index.ts";
import type { GetAssertionOptions } from "../src/index.ts";

const options: GetAssertionOptions = {
  challenge: new Uint8Array(32).fill(1),
  rpId: "example.com",
  allowCredentials: [
    {
      type: "public-key",
      id: "AQI",
      transports: ["internal"],
    },
  ],
  userVerification: "required",
  timeout: 100,
};

async function withNavigator(get: (options: CredentialRequestOptions) => Promise<unknown>, fn: () => Promise<void>) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { credentials: { get } },
  });
  try {
    await fn();
  } finally {
    if (descriptor) {
      Object.defineProperty(globalThis, "navigator", descriptor);
    } else {
      Reflect.deleteProperty(globalThis, "navigator");
    }
  }
}

test("native toJSON receives decoded descriptors and exact challenge", async () => {
  const value = {
    id: "AQ",
    rawId: "AQ",
    type: "public-key",
    response: {
      clientDataJSON: "AQ",
      authenticatorData: "Ag",
      signature: "Aw",
    },
    clientExtensionResults: {},
  };
  let jsonCalls = 0;
  await withNavigator(async (opts) => {
    assert.deepEqual(new Uint8Array(opts.publicKey!.challenge as ArrayBuffer), options.challenge);
    const credential = opts.publicKey!.allowCredentials![0]!;
    assert.deepEqual(new Uint8Array(credential.id as ArrayBuffer), new Uint8Array([1, 2]));
    assert.deepEqual(credential.transports, ["internal"]);
    assert.equal(opts.publicKey!.rpId, "example.com");
    assert.equal(opts.publicKey!.userVerification, "required");
    return {
      type: "public-key",
      toJSON: () => {
        jsonCalls++;
        return value;
      },
    };
  }, async () => {
    assert.deepEqual(await navigatorGetAssertion(options), value);
    assert.equal(jsonCalls, 1);
  });
});

for (const userHandle of [null, new Uint8Array([4]).buffer]) {
  test(`ArrayBuffer fallback encodes response, userHandle ${userHandle === null ? "null" : "present"}`, async () => {
    await withNavigator(async () => ({
      id: "AQ",
      rawId: new Uint8Array([1]).buffer,
      type: "public-key",
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: new Uint8Array([2]).buffer,
        authenticatorData: new Uint8Array([3]).buffer,
        signature: new Uint8Array([5]).buffer,
        userHandle,
      },
      getClientExtensionResults: () => ({ appid: false }),
    }), async () => {
      assert.deepEqual(await navigatorGetAssertion(options), {
        id: "AQ",
        rawId: "AQ",
        type: "public-key",
        authenticatorAttachment: "platform",
        response: {
          clientDataJSON: "Ag",
          authenticatorData: "Aw",
          signature: "BQ",
          userHandle: userHandle === null ? null : "BA",
        },
        clientExtensionResults: { appid: false },
      });
    });
  });
}

test("null or unexpected credential is rejected", async () => {
  for (const value of [null, { type: "password" }]) {
    await withNavigator(async () => value, async () => {
      await assert.rejects(navigatorGetAssertion(options), TypeError);
    });
  }
});

test("WebAuthn cancellation propagates", async () => {
  const error = new DOMException("cancelled", "NotAllowedError");
  await withNavigator(async () => {
    throw error;
  }, async () => {
    await assert.rejects(navigatorGetAssertion(options), e => e === error);
  });
});
