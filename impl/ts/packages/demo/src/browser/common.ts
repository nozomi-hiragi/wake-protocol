// Small DOM helpers shared by the demo pages.

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

/** Runs `run` on click; a rejection is shown in the status element. */
export function action(id: string, status: HTMLElement, run: () => Promise<void>): void {
  element(id).addEventListener("click", () => {
    run().catch((e: unknown) => {
      status.textContent = errorText(e);
    });
  });
}
