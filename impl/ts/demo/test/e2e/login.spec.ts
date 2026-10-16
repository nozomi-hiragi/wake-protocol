// Browser passkey login with WAKE-KX and messages over WAKE-SM, using a CDP virtual authenticator.
import { expect, test } from "@playwright/test";
import type { CDPSession, Page } from "@playwright/test";

async function open(page: Page, username: string): Promise<{ authenticatorId: string; cdp: CDPSession; }> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
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
  return { authenticatorId, cdp };
}

test("register, discoverable login, session, logout", async ({ page }) => {
  await open(page, "alice");
  const wires: Buffer[] = [];
  page.on("request", (request) => {
    const body = request.postDataBuffer();
    if (request.method() === "POST" && new URL(request.url()).pathname === "/wake/up" && body) {
      wires.push(body);
    }
  });
  await page.getByTestId("login-discoverable").click();
  await expect(page.getByTestId("status")).toContainText("logged in");
  await page.getByTestId("session").click();
  await expect(page.getByTestId("status")).toContainText("epoch 0");
  await expect(page.getByTestId("session-output")).toContainText("\"sessionId\"");
  await expect(page.getByTestId("session-output")).toContainText("\"epoch\": 0");
  const wire = wires.at(-1);
  expect(wire).toBeDefined();
  const replay = () => page.request.post("/wake/up", { headers: { "content-type": "application/wake" }, data: wire! });
  // Replays within the freshness window are not rejected (spec §8.4), so the 401 below is caused by the logout.
  expect((await replay()).status()).toBe(200);
  await page.getByTestId("logout").click();
  await expect(page.getByTestId("status")).toHaveText("logged out");
  await page.getByTestId("session").click();
  await expect(page.getByTestId("status")).toHaveText("error: reauth");
  const rejected = await replay();
  expect(rejected.status()).toBe(401);
  expect(await rejected.json()).toEqual({ wakeError: "reauth" });
});

test("login with username", async ({ page }) => {
  await open(page, "bob");
  await page.getByTestId("login-username").click();
  await expect(page.getByTestId("status")).toContainText("logged in");
  await page.getByTestId("session").click();
  await expect(page.getByTestId("status")).toContainText("epoch 0");
});

test("login fails when user verification fails", async ({ page }) => {
  const { authenticatorId, cdp } = await open(page, "carol");
  await cdp.send("WebAuthn.setUserVerified", { authenticatorId, isUserVerified: false });
  await page.getByTestId("login-discoverable").click();
  await expect(page.getByTestId("status")).toContainText("error:");
  await expect(page.getByTestId("status")).not.toContainText("logged in");
  await page.getByTestId("session").click();
  await expect(page.getByTestId("status")).toHaveText("error: reauth");
});
