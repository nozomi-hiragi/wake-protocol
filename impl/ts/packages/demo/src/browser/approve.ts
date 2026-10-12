// Approve page (spec §10.11): verify the operation, show the exact hashInput, then approve, approve + rekey, or reject.
import { WakeClient, navigatorGetAssertion, segmentHashInput } from "@wake-protocol/client";
import type { VerifiedOperation } from "@wake-protocol/client";
import { action, element } from "./common.ts";

const client = new WakeClient({ baseUrl: "", getAssertion: navigatorGetAssertion });
const status = element("status");
const hashView = element("hash-input");
const toggle = element<HTMLInputElement>("newline-toggle");
const buttons = ["approve", "approve-rekey", "reject"].map(id => element<HTMLButtonElement>(id));
const match = /^\/approve\/([0-9a-f]{64})$/u.exec(location.pathname);
const operationId = match?.[1];
let loaded: VerifiedOperation | undefined;

function show(text: string): void {
  status.textContent = text;
}

function codePointLabel(codePoint: number): string {
  return `U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}`;
}

// Presentation only: segments never change the hashInput that was verified and is signed over.
function render(): void {
  if (!loaded) {
    return;
  }
  const nodes: Node[] = [];
  for (const segment of segmentHashInput(loaded.hashInput, { newlines: toggle.checked ? "break" : "literal" })) {
    const span = document.createElement("span");
    span.dir = "ltr";
    if (segment.kind === "plain") {
      span.textContent = segment.text;
    } else if (segment.kind === "space") {
      span.className = "space";
      span.textContent = " ";
    } else if (segment.kind === "newline-marker") {
      span.className = "nl";
      // The real line break before the nonce line is drawn as a pilcrow; an escaped "\n" keeps its own text.
      span.textContent = segment.text === "\n" ? "⏎" : segment.text;
      nodes.push(span, document.createElement("br"));
      continue;
    } else {
      span.className = "badge";
      span.textContent = codePointLabel(segment.codePoint);
      span.title = `code point ${codePointLabel(segment.codePoint)}`;
    }
    nodes.push(span);
  }
  hashView.replaceChildren(...nodes);
}

function enable(on: boolean): void {
  for (const button of buttons) {
    button.disabled = !on;
  }
}

function requireId(): string {
  if (!operationId) {
    throw new Error("bad operation id in the URL");
  }
  return operationId;
}

async function load(): Promise<void> {
  const id = requireId();
  element("operation-id").textContent = id;
  // getOperation recomputes the operationId from content and nonce and rejects a mismatch (operation_mismatch).
  loaded = await client.getOperation(id);
  render();
  enable(loaded.status === "PENDING");
  show(`loaded: ${loaded.status}`);
}

toggle.addEventListener("change", render);

action("login-discoverable", status, async () => {
  const info = await client.login({ mode: "discoverable" });
  show(`logged in: epoch ${info.epoch}`);
  await load();
});

action("approve", status, async () => {
  const info = await client.approve(requireId());
  show(`approve: ${info.ta.result} (${info.ta.status})`);
  enable(false);
});

action("approve-rekey", status, async () => {
  const info = await client.approve(requireId(), { rekey: true });
  const kr = info.kr;
  const rekey = kr === undefined ? "none" : kr.result === "committed" ? `committed epoch ${kr.epoch}` : kr.result;
  show(`approve: ${info.ta.result} (${info.ta.status}); rekey: ${rekey}`);
  enable(false);
});

action("reject", status, async () => {
  const info = await client.reject(requireId());
  show(`reject: ${info.result} (${info.status})`);
  enable(false);
});
