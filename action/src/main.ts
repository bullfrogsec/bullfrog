import * as core from "@actions/core";
import fs from "node:fs/promises";
import util from "node:util";
import { exec as execCb, spawn, spawnSync } from "node:child_process";
import path from "node:path";
import {
  AGENT_LOG_FILENAME,
  AGENT_INSTALL_PATH,
  AGENT_READY_PATH,
} from "./constants";
import { parseInputs, EgressPolicy, DnsPolicy } from "./inputs";
import { waitForFile } from "./util";

const exec = util.promisify(execCb);

async function downloadAgent(actionDirectory: string): Promise<void> {
  const { status } = spawnSync(
    "bash",
    [path.join(actionDirectory, "scripts", "download_agent.sh")],
    {
      stdio: "inherit",
    },
  );

  if (status !== 0) {
    throw new Error("Couldn't download agent");
  }
}

function installPackages(): void {
  console.log("Installing packages");

  const { status } = spawnSync(
    "sudo",
    ["apt-get", "install", "-y", "libnetfilter-queue-dev", "nftables"],
    { stdio: "inherit" },
  );

  if (status !== 0) {
    throw new Error("Couldn't install packages");
  }
}

async function startAgent({
  agentLogFilepath,
  allowedDomains,
  allowedIps,
  dnsPolicy,
  egressPolicy,
  enableSudo,
  collectProcessInfo,
}: {
  allowedDomains: string[];
  allowedIps: string[];
  agentLogFilepath: string;
  dnsPolicy: DnsPolicy;
  egressPolicy: EgressPolicy;
  enableSudo: boolean;
  collectProcessInfo: boolean;
}): Promise<void> {
  // fix buggy /etc/hosts entry in Github private repo runners
  // this misconfiguration causes the agent to fail to start
  await exec(`sudo sed -i 's/^-e //' /etc/hosts`);

  const agentOut = await fs.open(agentLogFilepath, "a");
  console.log(`Starting agent from ${AGENT_INSTALL_PATH}`);
  console.time("Agent startup time");

  // make agent executable
  await exec(`sudo chmod +x ${AGENT_INSTALL_PATH}`);

  const allowedDomainsFlag =
    allowedDomains.length > 0
      ? `--allowed-domains ${allowedDomains.join(",")}`
      : "";

  const allowedIpsFlag =
    allowedIps.length > 0 ? `--allowed-ips ${allowedIps.join(",")}` : "";

  const enableSudoFlag = enableSudo ? "true" : "false";
  const collectProcessInfoFlag = collectProcessInfo ? "true" : "false";

  const agentCommand = [
    AGENT_INSTALL_PATH,
    "--dns-policy",
    dnsPolicy,
    "--egress-policy",
    egressPolicy,
    `--enable-sudo=${enableSudoFlag}`,
    `--collect-process-info=${collectProcessInfoFlag}`,
    allowedDomainsFlag,
    allowedIpsFlag,
    "--tetragon-path=/usr/local/bin/tetragon",
  ].join(" ");

  spawn("sudo", ["sh", "-c", agentCommand], {
    stdio: ["ignore", agentOut.fd, agentOut.fd],
    detached: true,
  }).unref();

  await agentOut.close();

  const agentReady = await waitForFile(AGENT_READY_PATH);
  if (!agentReady) {
    throw new Error("Agent could not start");
  }
  console.timeEnd("Agent startup time");
}

async function main(): Promise<void> {
  const {
    allowedDomains,
    allowedIps,
    dnsPolicy,
    egressPolicy,
    enableSudo,
    collectProcessInfo,
    logDirectory,
    apiToken,
    controlPlaneApiBaseUrl,
  } = parseInputs();

  const actionDirectory = path.join(__dirname, "..");

  // Add control plane domain to allowed domains if API token is provided
  if (apiToken && controlPlaneApiBaseUrl) {
    try {
      const url = new URL(controlPlaneApiBaseUrl);
      const controlPlaneDomain = url.hostname;
      allowedDomains.push(controlPlaneDomain);
      core.info(
        `Added control plane domain to allowed domains: ${controlPlaneDomain}`,
      );
    } catch (error) {
      core.warning(
        `Failed to parse control plane URL: ${error instanceof Error ? error.message : String(error)}. Connection results will not be published to Bullfrog's control plane.`,
      );
    }
  }

  await fs.mkdir(logDirectory, { recursive: true });

  const agentLogFilepath = path.join(logDirectory, AGENT_LOG_FILENAME);

  installPackages();

  await downloadAgent(actionDirectory);

  await startAgent({
    agentLogFilepath,
    allowedDomains,
    allowedIps,
    dnsPolicy,
    enableSudo,
    collectProcessInfo,
    egressPolicy,
  });
}

main().catch((error) => {
  console.error(error);
  core.setFailed(error);
  process.exit(1);
});
