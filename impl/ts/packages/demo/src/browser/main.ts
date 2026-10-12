// Browser entry for the demo: WakeClient with the platform authenticator.
import { base64urlnopad } from "@scure/base";
import { WakeClient, navigatorGetAssertion } from "@wake-protocol/client";
import { action as bindAction, element } from "./common.ts";

const client = new WakeClient({ baseUrl: "", getAssertion: navigatorGetAssertion });

const status = element("status");
const output = element("session-output");
const usernameInput = element<HTMLInputElement>("username");
const contentInput = element<HTMLInputElement>("content");
const operationIdInput = element<HTMLInputElement>("operation-id-input");
const operationLink = element("operation-link");
const operationOutput = element("operation-output");

function show(text: string): void {
  status.textContent = text;
}

async function post(path: string, body: unknown): Promise<Response> {
  return fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

function username(): string {
  return usernameInput.value.trim();
}

async function register(): Promise<void> {
  const name = username();
  const optionsResponse = await post("/register/options", { username: name });
  if (!optionsResponse.ok) {
    throw new Error(`register options failed: ${optionsResponse.status}`);
  }
  const options = await optionsResponse.json();
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: new Uint8Array(base64urlnopad.decode(options.challenge)),
      rp: options.rp,
      user: { ...options.user, id: new Uint8Array(base64urlnopad.decode(options.user.id)) },
      pubKeyCredParams: options.pubKeyCredParams,
      authenticatorSelection: options.authenticatorSelection,
      attestation: options.attestation,
      timeout: options.timeout,
    },
  }) as PublicKeyCredential | null;
  if (!credential) {
    throw new Error("no credential created");
  }
  const response = credential.response as AuthenticatorAttestationResponse;
  const publicKey = response.getPublicKey();
  if (!publicKey) {
    throw new Error("no public key");
  }
  const encode = (buffer: ArrayBuffer) => base64urlnopad.encode(new Uint8Array(buffer));
  const verified = await post("/register/verify", {
    username: name,
    credential: {
      id: credential.id,
      rawId: encode(credential.rawId),
      type: "public-key",
      response: {
        clientDataJSON: encode(response.clientDataJSON),
        authenticatorData: encode(response.getAuthenticatorData()),
        publicKey: encode(publicKey),
        publicKeyAlgorithm: response.getPublicKeyAlgorithm(),
        transports: response.getTransports(),
      },
    },
  });
  if (!verified.ok) {
    throw new Error(`register verify failed: ${verified.status}`);
  }
  show("registered");
}

function action(id: string, run: () => Promise<void>): void {
  bindAction(id, status, run);
}

action("register", register);

action("login-discoverable", async () => {
  const info = await client.login({ mode: "discoverable" });
  show(`logged in: ${info.sessionId} epoch ${info.epoch}`);
});

action("login-username", async () => {
  const info = await client.login({ mode: "username", username: username() });
  show(`logged in: ${info.sessionId} epoch ${info.epoch}`);
});

action("session", async () => {
  const info = await client.session();
  output.textContent = JSON.stringify(info, null, 2);
  show(`session: ${info.sessionId} epoch ${info.epoch}`);
});

action("logout", async () => {
  await client.logout();
  output.textContent = "";
  show("logged out");
});

action("rekey", async () => {
  const info = await client.rekey();
  show(`rekeyed: epoch ${info.epoch}`);
});

async function readJson(response: Response): Promise<Record<string, unknown>> {
  const value: unknown = await response.json();
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("unexpected response");
  }
  return value as Record<string, unknown>;
}

// Operations are created and read through WAKE-ET: /api/* is not an HTTP route.
action("create-operation", async () => {
  const response = await client.wakeFetch("/api/operations", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ content: contentInput.value }),
  });
  const body = await readJson(response);
  if (response.status !== 200 || typeof body.operationId !== "string" || !/^[0-9a-f]{64}$/u.test(body.operationId)) {
    const error = body.error;
    const code = error !== null && typeof error === "object" && "code" in error ? String(error.code) : String(response.status);
    show(`error: ${code}`);
    return;
  }
  operationIdInput.value = body.operationId;
  const link = document.createElement("a");
  link.href = `/approve/${body.operationId}`;
  link.textContent = "Open approve page";
  link.dataset.testid = "approve-link";
  operationLink.replaceChildren(link);
  show(`operation created: ${body.operationId}`);
});

action("check-operation", async () => {
  const id = operationIdInput.value.trim();
  const response = await client.wakeFetch(`/api/operation?id=${encodeURIComponent(id)}`);
  const body = await readJson(response);
  if (response.status !== 200 || typeof body.status !== "string") {
    const error = body.error;
    const code = error !== null && typeof error === "object" && "code" in error ? String(error.code) : String(response.status);
    show(`error: ${code}`);
    return;
  }
  operationOutput.textContent = JSON.stringify(body, null, 2);
  show(`operation: ${body.status}`);
});

action("me", async () => {
  const response = await client.wakeFetch("/api/me");
  const body = await readJson(response);
  operationOutput.textContent = JSON.stringify(body, null, 2);
  show(`me: epoch ${String(body.epoch)}`);
});
