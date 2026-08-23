import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  fetchPolicyOverride,
  applyPolicyOverride,
  type PolicyOverride,
} from "../policy";
import * as core from "@actions/core";
import type { Inputs } from "../inputs";

vi.mock("@actions/core");

function baseInputs(): Inputs {
  return {
    allowedDomains: ["workflow-domain.com"],
    allowedIps: ["1.2.3.4"],
    dnsPolicy: "any",
    egressPolicy: "audit",
    enableSudo: true,
    collectProcessInfo: true,
    logDirectory: "/var/log/test",
    controlPlaneApiBaseUrl: "https://api.example.com/",
    controlPlaneWebappBaseUrl: "https://app.example.com/",
    apiToken: "bullfrog_test-token",
    dryRunPrintConfig: false,
  };
}

describe("fetchPolicyOverride", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", vi.fn());
  });

  it("returns null without calling fetch when apiToken is missing", async () => {
    const result = await fetchPolicyOverride({
      apiToken: undefined,
      controlPlaneApiBaseUrl: "https://api.example.com/",
      repo: "acme/web",
    });
    expect(result).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("returns null without calling fetch when controlPlaneApiBaseUrl is missing", async () => {
    const result = await fetchPolicyOverride({
      apiToken: "bullfrog_test-token",
      controlPlaneApiBaseUrl: undefined,
      repo: "acme/web",
    });
    expect(result).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("returns the policy from a successful response", async () => {
    const policy: PolicyOverride = {
      allowedDomains: ["api.github.com"],
      allowedIps: [],
      dnsPolicy: "allowed-domains-only",
      egressPolicy: "block",
      enableSudo: false,
    };
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ policy }), { status: 200 }),
    );

    const result = await fetchPolicyOverride({
      apiToken: "bullfrog_test-token",
      controlPlaneApiBaseUrl: "https://api.example.com/",
      repo: "acme/web",
      workflow: ".github/workflows/release.yml",
      job: "publish",
    });

    expect(result).toEqual(policy);
    const [url, requestInit] = vi.mocked(fetch).mock.calls[0];
    expect(String(url)).toContain("v1/egress-policy");
    expect(
      (requestInit?.headers as Record<string, string>)?.Authorization,
    ).toBe("Bearer bullfrog_test-token");
  });

  it("returns null when the control plane has no matching policy", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ policy: null }), { status: 200 }),
    );

    const result = await fetchPolicyOverride({
      apiToken: "bullfrog_test-token",
      controlPlaneApiBaseUrl: "https://api.example.com/",
      repo: "acme/web",
    });

    expect(result).toBeNull();
  });

  it("returns null and warns on a non-2xx response", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response("unauthorized", { status: 401, statusText: "Unauthorized" }),
    );

    const result = await fetchPolicyOverride({
      apiToken: "bullfrog_test-token",
      controlPlaneApiBaseUrl: "https://api.example.com/",
      repo: "acme/web",
    });

    expect(result).toBeNull();
    expect(core.warning).toHaveBeenCalled();
  });

  it("returns null and warns when fetch throws", async () => {
    vi.mocked(fetch).mockRejectedValue(new Error("network down"));

    const result = await fetchPolicyOverride({
      apiToken: "bullfrog_test-token",
      controlPlaneApiBaseUrl: "https://api.example.com/",
      repo: "acme/web",
    });

    expect(result).toBeNull();
    expect(core.warning).toHaveBeenCalled();
  });
});

describe("applyPolicyOverride", () => {
  it("returns the base configuration unchanged when there is no override", () => {
    const base = baseInputs();
    expect(applyPolicyOverride(base, null)).toEqual(base);
  });

  it("wholesale replaces the base configuration when an override is present", () => {
    const base = baseInputs();
    const override: PolicyOverride = {
      allowedDomains: ["api.github.com"],
      allowedIps: [],
      dnsPolicy: "allowed-domains-only",
      egressPolicy: "block",
      enableSudo: false,
    };

    const resolved = applyPolicyOverride(base, override);

    expect(resolved.allowedDomains).toEqual(override.allowedDomains);
    expect(resolved.allowedIps).toEqual(override.allowedIps);
    expect(resolved.dnsPolicy).toBe(override.dnsPolicy);
    expect(resolved.egressPolicy).toBe(override.egressPolicy);
    expect(resolved.enableSudo).toBe(override.enableSudo);
    // Non-policy fields are untouched.
    expect(resolved.logDirectory).toBe(base.logDirectory);
    expect(resolved.apiToken).toBe(base.apiToken);
  });
});
