// One IndexedDB login shared by the demo's tabs. WebAuthn stays per page, so a new page copies the credential.
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { addVirtualAuthenticator, copyCredentials } from "./authenticator.ts";
import type { VirtualAuthenticator } from "./authenticator.ts";

async function registerAndLogin(page: Page, username: string): Promise<VirtualAuthenticator> {
  const auth = await addVirtualAuthenticator(page);
  await page.goto("/");
  await page.getByTestId("username").fill(username);
  await page.getByTestId("register").click();
  await expect(page.getByTestId("status")).toHaveText("registered");
  await page.getByTestId("login-discoverable").click();
  await expect(page.getByTestId("status")).toContainText("logged in");
  return auth;
}

async function createOperation(page: Page, content: string): Promise<string> {
  await page.getByTestId("content").fill(content);
  await page.getByTestId("create-operation").click();
  await expect(page.getByTestId("status")).toContainText("operation created: ");
  const id = await page.getByTestId("operation-id-input").inputValue();
  expect(id).toMatch(/^[0-9a-f]{64}$/);
  return id;
}

test("tabs share one login, then a rekey and a logout", async ({ page }) => {
  const auth = await registerAndLogin(page, "judy");
  const id = await createOperation(page, "pay bob 1 EUR");
  const approve = await page.context().newPage();
  await copyCredentials(auth, await addVirtualAuthenticator(approve));
  await approve.goto(`/approve/${id}`);
  await expect(approve.getByTestId("status")).toHaveText("loaded: PENDING");

  const mainState = page.getByTestId("session-state");
  const approveState = approve.getByTestId("session-state");
  await expect(mainState).toHaveText(/^session: \S+ epoch 0$/);
  const shared = await mainState.innerText();
  await expect(approveState).toHaveText(shared);
  const sessionId = shared.slice("session: ".length, -" epoch 0".length);

  await approve.getByTestId("approve-rekey").click();
  await expect(approve.getByTestId("status")).toHaveText("approve: approved (APPROVED); rekey: committed epoch 1");
  await expect(mainState).toHaveText(`session: ${sessionId} epoch 1`);
  await page.getByTestId("me").click();
  await expect(page.getByTestId("status")).toHaveText("me: epoch 1");

  await approve.getByTestId("logout").click();
  await expect(approve.getByTestId("status")).toHaveText("logged out");
  await expect(mainState).toHaveText("logged out");
  await page.getByTestId("session").click();
  await expect(page.getByTestId("status")).toHaveText("error: reauth");
});

test("an approve page in a fresh context without a login asks for one", async ({ page, browser }) => {
  const auth = await registerAndLogin(page, "karl");
  const id = await createOperation(page, "fresh context");
  const other = await browser.newContext();
  try {
    const approve = await other.newPage();
    await copyCredentials(auth, await addVirtualAuthenticator(approve));
    await approve.goto(new URL(`/approve/${id}`, page.url()).href);
    await expect(approve.getByTestId("status")).toHaveText("log in to continue");
    await approve.getByTestId("login-discoverable").click();
    await expect(approve.getByTestId("status")).toHaveText("loaded: PENDING");
  } finally {
    await other.close();
  }
});
