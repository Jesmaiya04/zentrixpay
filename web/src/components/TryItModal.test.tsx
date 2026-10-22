import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TryItModal } from "./TryItModal.js";
import type { PublicApi } from "../api/apis.js";
import type { WalletState } from "../hooks/useWalletConnection.js";

vi.mock("../lib/x402Call.js", () => ({
  callUrl: (_base: string, path: string, query: string) =>
    `http://gw.test/api/api1${path}${query ? `?${query}` : ""}`,
  callPaidApi: vi.fn(),
}));

const api: PublicApi = {
  id: "api1",
  name: "Weather API",
  description: "Forecasts",
  price: "0.01",
  priceRules: [],
  currency: "USDC",
  walletAddress: "GPROVIDER",
  allowedMethods: ["GET", "POST"],
  tags: [],
  healthy: true,
  proxyUrl: "http://gw.test/api/api1",
  openapiUrl: null,
  onchain: { registered: false, contractId: "", txHash: null },
  createdAt: "2026-10-01T00:00:00Z",
};

const disconnectedWallet: WalletState = {
  status: "disconnected",
  address: null,
  error: null,
  connect: vi.fn(),
  disconnect: vi.fn(),
};

const connectedWallet: WalletState = {
  ...disconnectedWallet,
  status: "connected",
  address: "G".padEnd(56, "A"),
};

function renderModal(onClose = vi.fn()) {
  return render(<TryItModal api={api} wallet={disconnectedWallet} onClose={onClose} />);
}

describe("TryItModal – accessibility", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders with role=dialog and aria-modal=true", () => {
    renderModal();
    expect(screen.getByRole("dialog")).toHaveAttribute("aria-modal", "true");
  });

  it("labels the dialog with the API name", () => {
    renderModal();
    const dialog = screen.getByRole("dialog");
    const labelId = dialog.getAttribute("aria-labelledby");
    expect(labelId).toBeTruthy();
    expect(document.getElementById(labelId!)).toHaveTextContent("Weather API");
  });

  it("closes on Escape key", async () => {
    const onClose = vi.fn();
    renderModal(onClose);
    await userEvent.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("closes when the × button is clicked", async () => {
    const onClose = vi.fn();
    renderModal(onClose);
    await userEvent.click(screen.getByRole("button", { name: /close/i }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("restores focus to the trigger element on close", () => {
    // Create a button outside the modal that acts as the trigger
    const trigger = document.createElement("button");
    trigger.textContent = "Open modal";
    document.body.appendChild(trigger);
    trigger.focus();
    expect(document.activeElement).toBe(trigger);

    // Mount the modal; unmounting runs the useEffect cleanup which restores focus
    const { unmount } = renderModal();
    unmount();

    expect(document.activeElement).toBe(trigger);

    document.body.removeChild(trigger);
  });

  it("traps focus: Tab from last focusable moves to first", async () => {
    renderModal();
    const dialog = screen.getByRole("dialog");
    const focusable = Array.from(
      dialog.querySelectorAll<HTMLElement>(
        "button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled])",
      ),
    );
    expect(focusable.length).toBeGreaterThan(1);

    const last = focusable[focusable.length - 1];
    const first = focusable[0];

    last.focus();
    expect(document.activeElement).toBe(last);

    await userEvent.tab();
    // Focus should wrap back to the first focusable element inside the dialog
    expect(dialog.contains(document.activeElement)).toBe(true);
    expect(document.activeElement).toBe(first);
  });

  it("traps focus: Shift+Tab from first focusable moves to last", async () => {
    renderModal();
    const dialog = screen.getByRole("dialog");
    const focusable = Array.from(
      dialog.querySelectorAll<HTMLElement>(
        "button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled])",
      ),
    );

    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    first.focus();
    expect(document.activeElement).toBe(first);

    await userEvent.tab({ shift: true });
    expect(document.activeElement).toBe(last);
  });

  it("sends headers entered in the request headers editor", async () => {
    vi.mocked(callPaidApi).mockResolvedValue({
      status: 200,
      charged: true,
      price: "0.01",
      contentType: "application/json",
      body: { ok: true },
    });
    render(<TryItModal api={api} wallet={connectedWallet} onClose={vi.fn()} />);

    await userEvent.click(screen.getByRole("button", { name: "Add header" }));
    await userEvent.type(screen.getByLabelText("Header name 1"), "x-tenant-key");
    await userEvent.type(screen.getByLabelText("Header value 1"), "tenant-123");
    await userEvent.click(screen.getByRole("button", { name: "Send request" }));

    expect(callPaidApi).toHaveBeenCalledWith(
      api.proxyUrl,
      connectedWallet.address,
      expect.objectContaining({ headers: { "x-tenant-key": "tenant-123" } }),
    );
  });
});
