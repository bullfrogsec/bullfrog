import * as core from "@actions/core";
import fs from "node:fs/promises";
import path from "node:path";
import { RESOLVED_CONFIG_FILENAME } from "./constants";
import { Inputs, DnsPolicy, EgressPolicy } from "./inputs";

export interface PolicyOverride {
  allowedDomains: string[];
  allowedIps: string[];
  dnsPolicy: DnsPolicy;
  egressPolicy: EgressPolicy;
  enableSudo: boolean;
}

export interface ResolvedConfig {
  allowedDomains: string[];
  allowedIps: string[];
  dnsPolicy: DnsPolicy;
  egressPolicy: EgressPolicy;
  enableSudo: boolean;
}

// Fetches the egress policy the control plane has configured for this job,
// if any. Failures (missing token/URL, network error, non-2xx response) are
// swallowed and reported as a warning: a control-plane outage or an
// unconfigured job must never break a build, so the caller falls back to the
// action's own input-based configuration.
export async function fetchPolicyOverride({
  apiToken,
  controlPlaneApiBaseUrl,
  repo,
  workflow,
  job,
}: {
  apiToken?: string;
  controlPlaneApiBaseUrl?: string;
  repo: string;
  workflow?: string;
  job?: string;
}): Promise<PolicyOverride | null> {
  if (!apiToken || !controlPlaneApiBaseUrl) {
    return null;
  }

  try {
    const url = new URL(`${controlPlaneApiBaseUrl}v1/egress-policy`);
    url.searchParams.set("repo", repo);
    url.searchParams.set("workflow", workflow ?? "");
    url.searchParams.set("job", job ?? "");

    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${apiToken}` },
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `Failed to fetch egress policy: ${response.status} ${response.statusText} - ${errorText}`,
      );
    }

    const { policy } = (await response.json()) as {
      policy: PolicyOverride | null;
    };
    return policy;
  } catch (error) {
    core.warning(
      `Failed to fetch egress policy from control plane: ${error instanceof Error ? error.message : String(error)}. Using the action's own configuration.`,
    );
    return null;
  }
}

// Applies a control-plane policy override on top of the action's own
// input-based configuration. When present, the override REPLACES
// allowedDomains/allowedIps/dnsPolicy/egressPolicy/enableSudo wholesale -
// the control plane's decision takes precedence over whatever the workflow
// author configured. When absent, the base configuration is returned
// unchanged.
export function applyPolicyOverride(
  base: Inputs,
  override: PolicyOverride | null,
): Inputs {
  if (!override) {
    return base;
  }

  return {
    ...base,
    allowedDomains: override.allowedDomains,
    allowedIps: override.allowedIps,
    dnsPolicy: override.dnsPolicy,
    egressPolicy: override.egressPolicy,
    enableSudo: override.enableSudo,
  };
}

export async function writeResolvedConfig(
  logDirectory: string,
  config: ResolvedConfig,
): Promise<void> {
  const filePath = path.join(logDirectory, RESOLVED_CONFIG_FILENAME);
  await fs.writeFile(filePath, JSON.stringify(config), "utf8");
}

export async function readResolvedConfig(
  logDirectory: string,
): Promise<ResolvedConfig | null> {
  try {
    const filePath = path.join(logDirectory, RESOLVED_CONFIG_FILENAME);
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw) as ResolvedConfig;
  } catch {
    return null;
  }
}
