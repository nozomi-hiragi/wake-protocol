// Browser WAKE-KR, WAKE-TA and WAKE-ET with a CDP virtual authenticator.
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

async function open(page: Page, username: string): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
    },
  });
  await page.goto("/");
  await page.getByTestId("username").fill(username);
  await page.getByTestId("register").click();
  await expect(page.getByTestId("status")).toHaveText("registered");
  await page.getByTestId("login-discoverable").click();
  await expect(page.getByTestId("status")).toContainText("logged in");
}

// Creates an operation on the main page and opens its approve page (same tab: the virtual authenticator is per page).
async function createAndOpen(page: Page, content: string): Promise<string> {
  await page.getByTestId("content").fill(content);
  await page.getByTestId("create-operation").click();
  await expect(page.getByTestId("status")).toContainText("operation created: ");
  const id = (await page.getByTestId("operation-id-input").inputValue());
  expect(id).toMatch(/^[0-9a-f]{64}$/);
  await page.getByTestId("approve-link").click();
  await expect(page).toHaveURL(new RegExp(`/approve/${id}$`));
  await page.getByTestId("login-discoverable").click();
  await expect(page.getByTestId("status")).toHaveText("loaded: PENDING");
  await expect(page.getByTestId("operation-id")).toHaveText(id);
  return id;
}

async function checkOnMainPage(page: Page, id: string): Promise<void> {
  await page.goto("/");
  await page.getByTestId("login-discoverable").click();
  await expect(page.getByTestId("status")).toContainText("logged in");
  await page.getByTestId("operation-id-input").fill(id);
  await page.getByTestId("check-operation").click();
}

test("rekey moves the session to epoch 1", async ({ page }) => {
  await open(page, "dave");
  await page.getByTestId("rekey").click();
  await expect(page.getByTestId("status")).toHaveText("rekeyed: epoch 1");
  await page.getByTestId("session").click();
  await expect(page.getByTestId("status")).toContainText("epoch 1");
  await expect(page.getByTestId("session-output")).toContainText("\"epoch\": 1");
  await page.getByTestId("me").click();
  await expect(page.getByTestId("status")).toHaveText("me: epoch 1");
});

test("create an operation, approve it on the approve page, see APPROVED", async ({ page }) => {
  await open(page, "erin");
  const id = await createAndOpen(page, "pay alice 10 EUR");
  const hash = page.getByTestId("hash-input");
  await expect(hash).toContainText("pay alice 10 EUR");
  await expect(hash).toContainText("WAKE-TA-Nonce: ");
  await page.getByTestId("approve").click();
  await expect(page.getByTestId("status")).toHaveText("approve: approved (APPROVED)");
  await checkOnMainPage(page, id);
  await expect(page.getByTestId("status")).toHaveText("operation: APPROVED");
  await expect(page.getByTestId("operation-output")).toContainText("\"decisionRecord\"");
});

test("reject shows REJECTED", async ({ page }) => {
  await open(page, "frank");
  const id = await createAndOpen(page, "delete my account");
  await page.getByTestId("reject").click();
  await expect(page.getByTestId("status")).toHaveText("reject: rejected (REJECTED)");
  await checkOnMainPage(page, id);
  await expect(page.getByTestId("status")).toHaveText("operation: REJECTED");
});

test("approve + rekey increments the epoch", async ({ page }) => {
  await open(page, "grace");
  const id = await createAndOpen(page, "transfer and rotate");
  await page.getByTestId("approve-rekey").click();
  await expect(page.getByTestId("status")).toHaveText("approve: approved (APPROVED); rekey: committed epoch 1");
  await checkOnMainPage(page, id);
  await expect(page.getByTestId("status")).toHaveText("operation: APPROVED");
});

test("a bidi control in the content is shown as a visible code point badge", async ({ page }) => {
  await open(page, "heidi");
  await createAndOpen(page, "pay ‮alice 10");
  const hash = page.getByTestId("hash-input");
  await expect(hash.locator(".badge", { hasText: "U+202E" })).toHaveCount(1);
  // The control character itself is never put in the DOM.
  expect(await hash.evaluate(node => node.textContent!.includes("‮"))).toBe(false);
  await expect(hash).toContainText("WAKE-TA-Nonce: ");
});

test("the newline toggle changes only the presentation", async ({ page }) => {
  await open(page, "ivan");
  await createAndOpen(page, "line one\\nline two");
  const hash = page.getByTestId("hash-input");
  await expect(hash.locator("br")).toHaveCount(1);
  await expect(hash.locator(".nl")).toHaveCount(1);
  await expect(hash).toContainText("line one\\nline two");
  await page.getByTestId("newline-toggle").check();
  await expect(hash.locator("br")).toHaveCount(2);
  await expect(hash).toContainText("line one");
  // The escaped pair becomes a marker element (it keeps its text) in addition to the real line break marker.
  await expect(hash.locator(".nl")).toHaveCount(2);
  await page.getByTestId("newline-toggle").uncheck();
  await expect(hash.locator("br")).toHaveCount(1);
  await expect(hash.locator(".nl")).toHaveCount(1);
});
