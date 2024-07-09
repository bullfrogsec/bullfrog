import * as core from "@actions/core";
import fs from "node:fs/promises";
import util from "node:util";
import { exec as execCb, spawn, spawnSync } from "node:child_process";
import path from "node:path";
import {
  AGENT_LOG_FILENAME,
  TETRAGON_LOG_FILENAME,
  BLOCK,
  ALLOWED_DOMAINS_ONLY,
  AGENT_INSTALL_PATH,
  AGENT_READY_PATH,
} from "./constants";
import { parseInputs, EgressPolicy, DnsPolicy } from "./inputs";
import { waitForFile, waitForStringInFile } from "./util";

const exec = util.promisify(execCb);

function installPackages() {
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

function installTetragon({ actionDirectory }: { actionDirectory: string }) {
  console.log("Installing Tetragon");

  const { status } = spawnSync(
    "bash",
    [path.join(actionDirectory, "scripts", "install_tetragon.sh")],
    {
      stdio: "inherit",
      env: {
        TETRAGON_POLICIES_DIRECTORY: path.join(actionDirectory, "tetragon"),
      },
    },
  );

  if (status !== 0) {
    throw new Error("Couldn't install Tetragon");
  }
}

async function startTetragon({
  tetragonLogFilepath,
}: {
  tetragonLogFilepath: string;
}) {
  const out = await fs.open(tetragonLogFilepath, "a");

  core.debug("Starting Tetragon");
  console.time("Tetragon startup time");

  spawn(
    "sudo",
    [
      "tetragon",
      "--export-file-max-size-mb",
      "1000",
      "--export-file-perm",
      "644",
      "--export-allowlist",
      '{"event_set": ["PROCESS_KPROBE"], "policy_names": ["connect"]}',
    ],
    {
      stdio: ["ignore", out.fd, out.fd],
      detached: true,
    },
  ).unref();

  await out.close();

  await waitForStringInFile({
    filePath: tetragonLogFilepath,
    str: "Listening for events...",
    timeoutMs: 15_000,
  });

  console.timeEnd("Tetragon startup time");
}

async function downloadAgent({
  actionDirectory,
  localAgentPath,
  version,
  agentDownloadBaseURL,
}: {
  actionDirectory: string;
  localAgentPath: string;
  version: string;
  agentDownloadBaseURL: string;
}): Promise<string> {
  if (localAgentPath !== "") {
    const absolutePath = path.join(actionDirectory, "..", localAgentPath);
    core.debug(`Using local agent from ${absolutePath}`);
    return absolutePath;
  }
  console.log(`Downloading agent v${version}`);

  const { status } = spawnSync(
    "bash",
    [
      path.join(actionDirectory, "scripts", "download_agent.sh"),
      `v${version}`,
      agentDownloadBaseURL,
    ],
    { stdio: "inherit" },
  );

  if (status !== 0) {
    throw new Error("Couldn't download agent");
  }

  return AGENT_INSTALL_PATH;
}

async function startAgent({
  agentDirectory,
  dnsPolicy,
  egressPolicy,
  allowedDomains,
  allowedIps,
  agentLogFilepath,
  agentPath,
}: {
  agentDirectory: string;
  dnsPolicy: DnsPolicy;
  egressPolicy: EgressPolicy;
  allowedDomains: string[];
  allowedIps: string[];
  agentLogFilepath: string;
  agentPath: string;
}) {
  const blockingMode = egressPolicy === BLOCK;

  console.log("Loading nftables rules");

  if (blockingMode && dnsPolicy === ALLOWED_DOMAINS_ONLY) {
    await exec(
      `sudo nft -f ${path.join(agentDirectory, "queue_block_with_dns.nft")}`,
    );
    console.log("loaded blocking rules (with DNS)");
  } else if (blockingMode) {
    await exec(`sudo nft -f ${path.join(agentDirectory, "queue_block.nft")}`);
    console.log("loaded blocking rules");
  } else {
    await exec(`sudo nft -f ${path.join(agentDirectory, "queue_audit.nft")}`);
    console.log("loaded audit rules");
  }

  const agentOut = await fs.open(agentLogFilepath, "a");
  console.log(`Starting agent from ${agentPath}`);
  console.time("Agent startup time");

  // make agent executable
  await exec(`sudo chmod +x ${agentPath}`);

  const allowedDomainsFlag =
    allowedDomains.length > 0
      ? `--allowed-domains ${allowedDomains.join(",")}`
      : "";
  const allowedIpsFlag =
    allowedIps.length > 0 ? `--allowed-ips ${allowedIps.join(",")}` : "";

  spawn(
    "sudo",
    [
      "sh",
      "-c",
      `${agentPath} --dns-policy ${dnsPolicy} --egress-policy ${egressPolicy} ${allowedDomainsFlag} ${allowedIpsFlag}`,
    ],
    {
      stdio: ["ignore", agentOut.fd, agentOut.fd],
      detached: true,
    },
  ).unref();

  await agentOut.close();

  const agentReady = await waitForFile(AGENT_READY_PATH);
  if (!agentReady) {
    throw new Error("Agent could not start");
  }
  console.timeEnd("Agent startup time");
}

async function main() {
  const {
    allowedDomains,
    allowedIps,
    dnsPolicy,
    egressPolicy,
    logDirectory,
    localAgentPath,
    agentDownloadBaseURL,
  } = parseInputs();

  const actionDirectory = path.join(__dirname, "..");

  const agentDirectory = path.join(actionDirectory, "..", "agent");
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const pkg = require(`${actionDirectory}/../package.json`);

  await fs.mkdir(logDirectory, { recursive: true });

  if (allowedDomains.length !== 0) {
    await fs.writeFile("allowed_domains.txt", allowedDomains.join("\n"));
  }

  if (allowedIps.length !== 0) {
    await fs.writeFile("allowed_ips.txt", allowedIps.join("\n"));
  }

  const agentLogFilepath = path.join(logDirectory, AGENT_LOG_FILENAME);
  const tetragonLogFilepath = path.join(logDirectory, TETRAGON_LOG_FILENAME);

  installPackages();
  installTetragon({ actionDirectory });
  await startTetragon({
    tetragonLogFilepath,
  });
  const agentPath = await downloadAgent({
    actionDirectory,
    localAgentPath,
    version: pkg.version,
    agentDownloadBaseURL,
  });
  await startAgent({
    agentDirectory,
    dnsPolicy,
    egressPolicy,
    allowedDomains,
    allowedIps,
    agentLogFilepath,
    agentPath,
  });
}

main().catch((error) => {
  console.error(error);
  core.setFailed(error);
  process.exit(1);
});
