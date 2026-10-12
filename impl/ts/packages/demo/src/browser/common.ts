// Small DOM helpers shared by the demo pages.
import { WakeClient, indexedDbSessionStore, navigatorGetAssertion } from "@wake-protocol/client";
import type { SessionStore, StoredSessionInfo } from "@wake-protocol/client";

/** One client per page, backed by the origin's shared IndexedDB session. */
export function createClient(): { client: WakeClient; store: SessionStore } {
  const store = indexedDbSessionStore();
  const client = new WakeClient({ baseUrl: "", getAssertion: navigatorGetAssertion, store });
  return { client, store };
}

function sessionText(info: StoredSessionInfo | undefined): string {
  if (info === undefined) {
    return "logged out";
  }
  return `session: ${info.sessionId} epoch ${info.epoch}`;
}

export function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) {
    throw new Error(`missing element ${id}`);
  }
  return found as T;
}

export function errorText(e: unknown): string {
  const code = e instanceof Error && "code" in e && typeof e.code === "string" ? e.code : undefined;
  return `error: ${code ?? (e instanceof Error ? e.name : "unknown")}`;
}

// trackSession installs this so a click repaints `#session-state` when it finishes.
let paintSession = (): void => {};

/** Runs `run` on click. A rejection is shown in the status element. The session element is repainted either way. */
export function action(id: string, status: HTMLElement, run: () => Promise<void>): void {
  element(id).addEventListener("click", () => {
    run().then(() => {
      paintSession();
    }, (e: unknown) => {
      status.textContent = errorText(e);
      paintSession();
    });
  });
}

/**
 * Keeps `#session-state` aligned with `client.currentSession`.
 * Reloads on page load, when the page becomes visible, on focus, and on every store notice.
 * One reload runs at a time; a notice during it queues one more.
 * `onChange` runs after each successful reload. A reload failure is written to `#status`.
 */
export function trackSession(
  client: WakeClient,
  store: SessionStore,
  onChange: (info: StoredSessionInfo | undefined) => void,
): void {
  const stateEl = element("session-state");
  const status = element("status");
  const paint = (): void => {
    stateEl.textContent = sessionText(client.currentSession);
  };
  paintSession = paint;

  let current: Promise<void> | undefined;
  let again = false;

  const cycle = async (): Promise<void> => {
    do {
      again = false;
      try {
        const info = await client.reload();
        paint();
        onChange(info);
      } catch (e: unknown) {
        status.textContent = errorText(e);
      }
    } while (again);
  };

  const refresh = (): void => {
    if (current !== undefined) {
      again = true;
      return;
    }
    current = cycle().finally(() => {
      current = undefined;
      if (again) {
        refresh();
      }
    });
  };

  store.subscribe(() => {
    refresh();
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      refresh();
    }
  });
  window.addEventListener("focus", () => {
    refresh();
  });
  refresh();
}
