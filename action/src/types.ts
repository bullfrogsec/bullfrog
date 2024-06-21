import * as core from "@actions/core";
import { AUDIT, BLOCK } from "./constants";

export type EgressPolicy = typeof AUDIT | typeof BLOCK;

export interface Inputs {
  allowedDomains: Array<string>;
  allowedIps: Array<string>;
  egressPolicy: EgressPolicy;
  blockDNS: boolean;
  logDirectory: string;
}

export function parseInputs(): Inputs {
  const rawAllowedIps = core.getInput("allowed-ips");

  const allowedIps =
    rawAllowedIps.length !== 0 ? rawAllowedIps.split("\n") : [];

  const rawAllowedDomains = core.getInput("allowed-domains");

  const allowedDomains =
    rawAllowedDomains.length !== 0 ? rawAllowedDomains.split("\n") : [];

  const egressPolicy = core.getInput("egress-policy") as EgressPolicy;

  if (![AUDIT, BLOCK].includes(egressPolicy)) {
    console.error(
      `Invalid egress policy: ${egressPolicy}. Defaulting to audit policy.`
    );
  }

  const blockDNS = core.getBooleanInput("block-dns");

  return {
    allowedDomains,
    allowedIps,
    egressPolicy,
    blockDNS,
    logDirectory: core.getInput("log-directory", { required: true }),
  };
}
