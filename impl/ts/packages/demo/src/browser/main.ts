// Browser entry for the demo: WakeClient with the platform authenticator.
import { base64urlnopad } from "@scure/base";
import { WakeClient, navigatorGetAssertion } from "@wake-protocol/client";

const client = new WakeClient({ baseUrl: "", getAssertion: navigatorGetAssertion });

function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) {
    throw new Error(`missing element ${id}`);
  }
  return found as T;
}

const status = element("status");
const output = element("session-output");
const usernameInput = element<HTMLInputElement>("username");

function show(text: string): void {
  status.textContent = text;
}

function fail(e: unknown): void {
  const code = e instanceof Error && "code" in e && typeof e.code === "string" ? e.code : undefined;
  show(`error: ${code ?? (e instanceof Error ? e.name : "unknown")}`);
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
  element(id).addEventListener("click", () => {
    run().catch(fail);
  });
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
