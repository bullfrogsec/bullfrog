import * as core from "@actions/core";
import { ALLOWED_DOMAINS_ONLY, ANY, AUDIT, BLOCK } from "./constants";

export type DnsPolicy = typeof ALLOWED_DOMAINS_ONLY | typeof ANY;
export type EgressPolicy = typeof AUDIT | typeof BLOCK;

export interface Inputs {
  allowedDomains: Array<string>;
  allowedIps: Array<string>;
  dnsPolicy: DnsPolicy;
  egressPolicy: EgressPolicy;
  logDirectory: string;
}

export function parseInputs(): Inputs {
  const rawAllowedIps = core.getInput("allowed-ips");

  const allowedIps =
    rawAllowedIps.length !== 0 ? rawAllowedIps.split("\n") : [];

  const rawAllowedDomains = core.getInput("allowed-domains");

  const allowedDomains =
    rawAllowedDomains.length !== 0 ? rawAllowedDomains.split("\n") : [];

  const egressPolicy = core.getInput("egress-policy");
  if (egressPolicy !== AUDIT && egressPolicy !== BLOCK) {
    throw new Error(`egress-policy must be '${AUDIT}' or '${BLOCK}'`);
  }

  const dnsPolicy = core.getInput("dns-policy");

  if (dnsPolicy !== ALLOWED_DOMAINS_ONLY && dnsPolicy !== ANY) {
    throw new Error(`dns-policy must be '${ALLOWED_DOMAINS_ONLY}' or '${ANY}'`);
  }

  return {
    allowedDomains,
    allowedIps,
    dnsPolicy,
    egressPolicy,
    logDirectory: core.getInput("log-directory", { required: true }),
  };
}
