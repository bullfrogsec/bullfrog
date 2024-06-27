import * as core from "@actions/core";
import fs from "node:fs/promises";
import util from "node:util";
import { exec as execCb, spawn, spawnSync } from "node:child_process";
import path from "node:path";
import {
  AGENT_LOG_FILENAME,
  CONNECT_LOG_FILENAME,
  TETRAGON_LOG_FILENAME,
  BLOCK,
  ALLOWED_DOMAINS_ONLY,
  AGENT_INSTALL_PATH,
  TETRAGON_EVENTS_LOG_PATH,
  AGENT_READY_PATH,
} from "./constants";
import { parseInputs, EgressPolicy, DnsPolicy } from "./inputs";
import { waitForFile } from "./util";

const exec = util.promisify(execCb);

function installPackages() {
  console.log("Installing packages");

  const { status } = spawnSync(
    "sudo",
    ["apt-get", "install", "-y", "libnetfilter-queue-dev", "nftables"],
    { stdio: "inherit" }
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
    }
  );

  if (status !== 0) {
    throw new Error("Couldn't install Tetragon");
  }
}

async function startTetragon({
  connectLogFilepath,
  tetragonLogFilepath,
}: {
  connectLogFilepath: string;
  tetragonLogFilepath: string;
}) {
  const out = (await fs.open(tetragonLogFilepath, "a")).fd;

  core.debug("Starting Tetragon");
  console.time("Tetragon startup time");
  spawn("sudo", ["tetragon"], {
    stdio: ["ignore", out, out],
    detached: true,
  }).unref();

  const tetragonReady = await waitForFile(TETRAGON_EVENTS_LOG_PATH);
  if (!tetragonReady) {
    throw new Error("Tetragon could not start");
  }
  console.timeEnd("Tetragon startup time");

  const connectOut = (await fs.open(connectLogFilepath, "a")).fd;
  spawn(
    `sudo tail -n +1 -F ${TETRAGON_EVENTS_LOG_PATH} | jq -c --unbuffered 'select(.process_kprobe.policy_name == "connect")'`,
    {
      shell: true,
      stdio: ["ignore", connectOut, "ignore"],
      detached: true,
    }
  ).unref();
}

async function downloadAgent({
  actionDirectory,
  localAgentPath,
  version,
}: {
  actionDirectory: string;
  localAgentPath: string;
  version: string;
}): Promise<string> {
  if (localAgentPath !== "") {
    const absolutePath = path.join(actionDirectory, "..", localAgentPath);
    core.debug(`Using local agent from ${absolutePath}`);
    return absolutePath;
  }
  console.log(`Downloading agent v${version}`);

  const { status } = spawnSync(
    "bash",
    [path.join(actionDirectory, "scripts", "download_agent.sh"), `v${version}`],
    { stdio: "inherit" }
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
  agentLogFilepath,
  agentPath,
}: {
  agentDirectory: string;
  dnsPolicy: DnsPolicy;
  egressPolicy: EgressPolicy;
  agentLogFilepath: string;
  agentPath: string;
}) {
  const blockingMode = egressPolicy === BLOCK;

  console.log("Loading nftables rules");

  if (blockingMode && dnsPolicy === ALLOWED_DOMAINS_ONLY) {
    await exec(
      `sudo nft -f ${path.join(agentDirectory, "queue_block_with_dns.nft")}`
    );
    console.log("loaded blocking rules (with DNS)");
  } else if (blockingMode) {
    await exec(`sudo nft -f ${path.join(agentDirectory, "queue_block.nft")}`);
    console.log("loaded blocking rules");
  } else {
    await exec(`sudo nft -f ${path.join(agentDirectory, "queue_audit.nft")}`);
    console.log("loaded audit rules");
  }

  const agentOut = (await fs.open(agentLogFilepath, "a")).fd;
  console.log(`Starting agent from ${agentPath}`);
  console.time("Agent startup time");

  // make agent executable
  await exec(`sudo chmod +x ${agentPath}`);

  spawn(
    "sudo",
    [agentPath, "--dns-policy", dnsPolicy, "--egress-policy", egressPolicy],
    {
      stdio: ["ignore", agentOut, agentOut],
      detached: true,
    }
  ).unref();

  const agentReady = await waitForFile(AGENT_READY_PATH);
  if (!agentReady) {
    throw new Error("Agent could not start");
  }
  console.timeEnd("Agent startup time");
}

async function _main() {
  const {
    allowedDomains,
    allowedIps,
    dnsPolicy,
    egressPolicy,
    logDirectory,
    localAgentPath,
  } = parseInputs();

  const actionDirectory = path.join(__dirname, "..");
  const agentDirectory = path.join(actionDirectory, "..", "agent");
  const pkg = require(`${actionDirectory}/../package.json`);

  await fs.mkdir(logDirectory, { recursive: true });

  if (allowedDomains.length !== 0) {
    await fs.writeFile("allowed_domains.txt", allowedDomains.join("\n"));
  }

  if (allowedIps.length !== 0) {
    await fs.writeFile("allowed_ips.txt", allowedIps.join("\n"));
  }

  const agentLogFilepath = path.join(logDirectory, AGENT_LOG_FILENAME);
  const connectLogFilepath = path.join(logDirectory, CONNECT_LOG_FILENAME);
  const tetragonLogFilepath = path.join(logDirectory, TETRAGON_LOG_FILENAME);

  installPackages();
  installTetragon({ actionDirectory });
  await startTetragon({
    connectLogFilepath,
    tetragonLogFilepath,
  });
  const agentPath = await downloadAgent({
    actionDirectory,
    localAgentPath,
    version: pkg.version,
  });
  await startAgent({
    agentDirectory,
    dnsPolicy,
    egressPolicy,
    agentLogFilepath,
    agentPath,
  });
}

async function main() {
  try {
    await _main();
  } catch (error: any) {
    console.error(error);
    core.setFailed(error);
    process.exit(1);
  }
}

// Main has a global try catch, it should never throw
main();
