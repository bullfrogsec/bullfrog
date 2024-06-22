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
} from "./constants";
import { parseInputs, EgressPolicy } from "./types";

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

  console.log("Starting Tetragon");

  spawn("sudo", ["tetragon"], {
    stdio: ["ignore", out, out],
    detached: true,
  }).unref();

  // TODO: Use a more reliable method to wait for Tetragon to be ready
  await new Promise((resolve) => setTimeout(resolve, 5000));

  const connectOut = (await fs.open(connectLogFilepath, "a")).fd;
  spawn(
    `sudo tail -n +1 -F /var/log/tetragon/tetragon.log | jq -c --unbuffered 'select(.process_kprobe.policy_name == "connect")'`,
    {
      shell: true,
      stdio: ["ignore", connectOut, "ignore"],
      detached: true,
    }
  ).unref();
}

async function startAgent({
  agentDirectory,
  egressPolicy,
  blockDNS,
  agentLogFilepath,
}: {
  agentDirectory: string;
  egressPolicy: EgressPolicy;
  blockDNS: boolean;
  agentLogFilepath: string;
}) {
  const blockingMode = egressPolicy === BLOCK;

  console.log("Loading nftables rules");

  if (blockingMode && blockDNS) {
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

  console.log("Starting agent");

  const agentOut = (await fs.open(agentLogFilepath, "a")).fd;
  spawn(
    "sudo",
    [
      path.join(agentDirectory, "agent"),
      "--mode",
      egressPolicy,
      blockDNS ? "--block-dns" : "",
    ],
    {
      stdio: ["ignore", agentOut, agentOut],
      detached: true,
    }
  ).unref();
}

async function _main() {
  const { allowedDomains, allowedIps, egressPolicy, blockDNS, logDirectory } =
    parseInputs();

  const actionDirectory = path.join(__dirname, "..");
  const agentDirectory = path.join(actionDirectory, "..", "agent");

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
  await startAgent({
    agentDirectory,
    egressPolicy,
    blockDNS,
    agentLogFilepath,
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
