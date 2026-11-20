import { expect, test } from "@playwright/test";
import { gotoAndWait, UI_READY_TIMEOUT } from "./helpers";

test.describe("Password generation", () => {
    test("generates a 32-character password", async ({ page }) => {
        await gotoAndWait(page, "/ui/generate-password");
        await expect(page.getByTestId("generate-password")).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await page.getByTestId("generate-password").click();
        await expect(page.getByTestId("generated-password")).toHaveValue(/^[A-Za-z0-9]{32}$/);
    });
});

test.describe("SSH CA, roles and certificates", () => {
    test("creates a CA, saves a role and signs a browser-generated key", async ({ page }) => {
        await gotoAndWait(page, "/ui/ssh-ca");
        await expect(page.getByTestId("submit-ssh-ca")).toBeVisible({ timeout: UI_READY_TIMEOUT });

        // Empty key ID: the UI creates a new EC key pair and uses it as the CA.
        await page.getByTestId("submit-ssh-ca").click();
        const outcome = page
            .getByTestId("ssh-ca-result")
            .getByText(/private key id/i)
            .or(page.getByText(/Crypto Officer is required/i).first());
        await expect(outcome).toBeVisible({ timeout: 60_000 });
        // CA and role endpoints require a configured Crypto Officer; skip on servers without one.
        test.skip(
            await page
                .getByText(/Crypto Officer is required/i)
                .first()
                .isVisible(),
            "server has no Crypto Officer configured",
        );
        await expect(page.getByTestId("ssh-ca-result")).toContainText(/private key id: [0-9a-f-]{36}/i, { timeout: 60_000 });
        await expect(page.getByTestId("ssh-ca-result")).toContainText(/ecdsa-sha2-nistp\d+ AAAA/);

        await page.getByTestId("ssh-ca-public-key").click();
        await expect(page.getByTestId("ssh-ca-result")).not.toContainText(/private key id/i);
        await expect(page.getByTestId("ssh-ca-result")).toContainText(/ecdsa-sha2-nistp\d+ AAAA/);

        await page.getByTestId("ssh-role-name").fill("e2e-role");
        await page.getByTestId("ssh-role-principals").fill("alice, bob");
        await page.getByTestId("ssh-role-default-ttl").fill("15m");
        await page.getByTestId("ssh-role-max-ttl").fill("1h");
        await page.getByTestId("submit-ssh-role").click();
        await expect(page.getByTestId("ssh-role-result")).toContainText("e2e-role");

        await gotoAndWait(page, "/ui/ssh-certificate");
        await expect(page.getByTestId("ssh-generate-key")).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await page.getByTestId("ssh-generate-key").click();
        await expect(page.getByTestId("ssh-public-key")).toHaveValue(/^ecdsa-sha2-nistp256 AAAA/);
        await page.getByTestId("ssh-role").fill("e2e-role");
        await page.getByTestId("ssh-principals").fill("alice");
        await page.getByTestId("ssh-ttl").fill("10m");
        await page.getByTestId("submit-ssh-certificate").click();
        await expect(page.getByTestId("response-output")).toContainText(/ecdsa-sha2-nistp256-cert-v01@openssh\.com AAAA/, {
            timeout: 60_000,
        });
    });

    test("rejects an invalid role name before calling the server", async ({ page }) => {
        await gotoAndWait(page, "/ui/ssh-ca");
        await expect(page.getByTestId("submit-ssh-role")).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await page.getByTestId("ssh-role-name").fill("bad name!");
        await page.getByTestId("ssh-role-principals").fill("alice");
        await page.getByTestId("submit-ssh-role").click();
        await expect(page.getByText(/1 to 64 letters/i)).toBeVisible();
        await expect(page.getByTestId("ssh-role-result")).not.toContainText("saved");
    });
});
