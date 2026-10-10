import { expect, type Page, test } from "@playwright/test";

async function loginAs(page: Page, name: string) {
  await page.goto("/");
  const signOut = page.getByRole("button", { name: "Sign out" });
  if (await signOut.isVisible().catch(() => false)) await signOut.click();
  await page.getByRole("button", { name: new RegExp(name) }).click();
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
}

test("investigate → inspect multi-hop path → approve simulated action → audit → persists", async ({ page }) => {
  // 1-4: investigator starts an investigation from the alerts explorer
  await loginAs(page, "Alice Analyst");
  await expect(page.getByText("Security overview")).toBeVisible();
  await page.getByRole("link", { name: "Alerts" }).first().click();
  await page.getByRole("button", { name: /ALT-1001/ }).click();
  await page.getByRole("button", { name: "Investigate ALT-1001" }).click();
  await page.getByRole("button", { name: "Investigate", exact: true }).click();

  // 5-8: agent runs graph tools; multi-hop path, evidence and deterministic risk appear
  await expect(page.getByText("completed", { exact: true })).toBeVisible({ timeout: 30_000 });
  const invUrl = page.url();
  expect(invUrl).toMatch(/\/investigations\/INV-/);
  await expect(page.getByText(/Selected path · [4-9] hops/)).toBeVisible();
  await expect(page.getByLabel("Risk score", { exact: false })).toBeVisible();
  await page.getByRole("tab", { name: /Evidence/ }).click();
  await expect(page.getByText("Contradicting (3)")).toBeVisible();
  await expect(page.getByText("excluded from scoring")).toBeVisible();
  await page.getByRole("tab", { name: "Risk" }).click();
  await expect(page.getByText(/score = 100 × Σ/)).toBeVisible();
  await page.getByRole("tab", { name: /Tool trace/ }).click();
  await expect(page.getByText("verified")).toBeVisible();

  // 9-10: requester cannot approve (four-eyes); approver can
  await page.getByRole("tab", { name: /Actions/ }).click();
  await expect(page.getByTestId("action-isolate_endpoint").getByRole("button", { name: /Approve/ })).toBeDisabled();
  await loginAs(page, "Bob Approver");
  await page.goto(invUrl);
  await page.getByRole("tab", { name: /Actions/ }).click();
  const card = page.getByTestId("action-isolate_endpoint");
  await card.getByRole("button", { name: /Approve/ }).click();
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "Approve & run simulation" }).click();
  await expect(card.getByText("Executed (simulation)")).toBeVisible();

  // 11: audit trail
  await page.getByRole("link", { name: "Audit trail" }).click();
  await expect(page.getByText(/Hash chain verified/)).toBeVisible();
  await expect(page.getByRole("table").getByText("action.executed_simulation").first()).toBeVisible();

  // 12: refresh — investigation persists
  await page.goto(invUrl);
  await page.reload();
  await expect(page.getByText("completed", { exact: true })).toBeVisible();
  await page.getByRole("tab", { name: /Actions/ }).click();
  await expect(page.getByTestId("action-isolate_endpoint").getByText("Executed (simulation)")).toBeVisible();
});

test("viewer cannot start investigations", async ({ page }) => {
  await loginAs(page, "Vera Viewer");
  await page.goto("/investigate");
  await expect(page.getByRole("button", { name: "Investigate", exact: true })).toBeDisabled();
});
