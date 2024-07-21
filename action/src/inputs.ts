import * as core from "@actions/core";
import { ALLOWED_DOMAINS_ONLY, ANY, AUDIT, BLOCK } from "./constants";

export type DnsPolicy = typeof ALLOWED_DOMAINS_ONLY | typeof ANY;
export type EgressPolicy = typeof AUDIT | typeof BLOCK;

export interface Inputs {
  allowedDomains: Array<string>;
  allowedIps: Array<string>;
  dnsPolicy: DnsPolicy;
  enableSudo: boolean;
  egressPolicy: EgressPolicy;
  localAgent: boolean;
  logDirectory: string;
  agentDownloadBaseURL: string;
}

function validateIps(ips: Array<string>): void {
  ips.forEach((ip) => {
    // validate the ip is valid
    if (!ip.match(/^[0-9./]+$/)) {
      throw new Error(`Invalid IP: ${ip}`);
    }
  });
}

function validateDomains(domains: Array<string>): void {
  domains.forEach((domain) => {
    // validate the domain is valid
    if (!domain.match(/^[A-Za-z0-9.\-*]+$/)) {
      throw new Error(`Invalid domain: ${domain}`);
    }
  });
}

export function parseInputs(): Inputs {
  const rawAllowedIps = core.getInput("allowed-ips");

  const allowedIps =
    rawAllowedIps.length !== 0 ? rawAllowedIps.split("\n") : [];

  validateIps(allowedIps);

  const rawAllowedDomains = core.getInput("allowed-domains");

  const allowedDomains =
    rawAllowedDomains.length !== 0 ? rawAllowedDomains.split("\n") : [];

  validateDomains(allowedDomains);

  const egressPolicy = core.getInput("egress-policy");
  if (egressPolicy !== AUDIT && egressPolicy !== BLOCK) {
    throw new Error(`egress-policy must be '${AUDIT}' or '${BLOCK}'`);
  }

  const dnsPolicy = core.getInput("dns-policy");

  if (dnsPolicy !== ALLOWED_DOMAINS_ONLY && dnsPolicy !== ANY) {
    throw new Error(`dns-policy must be '${ALLOWED_DOMAINS_ONLY}' or '${ANY}'`);
  }

  const localAgent = process.env["_LOCAL_AGENT"]?.toLowerCase() === "true";

  return {
    allowedDomains,
    allowedIps,
    dnsPolicy,
    enableSudo: core.getBooleanInput("enable-sudo"),
    egressPolicy,
    localAgent,
    logDirectory: core.getInput("_log-directory", { required: true }),
    agentDownloadBaseURL: core.getInput("_agent-download-base-url"),
  };
}
