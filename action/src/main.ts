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

async function copyLocalAgent({ agentDirectory }: { agentDirectory: string }) {
  await fs.mkdir(path.dirname(AGENT_INSTALL_PATH), { recursive: true });
  await fs.cp(path.join(agentDirectory, "agent"), AGENT_INSTALL_PATH);
}

async function downloadAgent({
  actionDirectory,
  agentDirectory,
  version,
  agentDownloadBaseURL,
}: {
  actionDirectory: string;
  agentDirectory: string;
  version: string;
  agentDownloadBaseURL: string;
}) {
  console.log(`Downloading agent v${version}`);

  const { status } = spawnSync(
    "bash",
    [
      path.join(actionDirectory, "scripts", "download_agent.sh"),
      `v${version}`,
      agentDownloadBaseURL,
    ],
    {
      env: {
        AGENT_DIRECTORY: agentDirectory,
      },
      stdio: "inherit",
    },
  );

  if (status !== 0) {
    throw new Error("Couldn't download agent");
  }
}

async function installAgent({
  actionDirectory,
  agentDirectory,
  localAgent,
  version,
  agentDownloadBaseURL,
}: {
  actionDirectory: string;
  agentDirectory: string;
  localAgent: boolean;
  version: string;
  agentDownloadBaseURL: string;
}): Promise<void> {
  if (localAgent) {
    await copyLocalAgent({ agentDirectory });
  } else {
    await downloadAgent({
      actionDirectory,
      agentDirectory,
      agentDownloadBaseURL,
      version,
    });
  }

  await verifyAgent({ agentDirectory });
}

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

async function startAgent({
  agentDirectory,
  agentLogFilepath,
  allowedDomains,
  allowedIps,
  dnsPolicy,
  egressPolicy,
  enableSudo,
}: {
  agentDirectory: string;
  allowedDomains: string[];
  allowedIps: string[];
  agentLogFilepath: string;
  dnsPolicy: DnsPolicy;
  egressPolicy: EgressPolicy;
  enableSudo: boolean;
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

  const agentCommand = [
    AGENT_INSTALL_PATH,
    "--dns-policy",
    dnsPolicy,
    "--egress-policy",
    egressPolicy,
    `--enable-sudo=${enableSudoFlag}`,
    allowedDomainsFlag,
    allowedIpsFlag,
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

async function verifyAgent({ agentDirectory }: { agentDirectory: string }) {
  const agentDirName = path.dirname(AGENT_INSTALL_PATH);

  const src = path.join(agentDirectory, "agent.sha256");
  const dest = path.join(agentDirName, "agent.sha256");

  await fs.cp(src, dest);

  await exec("sha256sum --check --strict agent.sha256", {
    cwd: agentDirName,
  });
}

async function main() {
  const {
    agentDownloadBaseURL,
    allowedDomains,
    allowedIps,
    dnsPolicy,
    egressPolicy,
    enableSudo,
    localAgent,
    logDirectory,
  } = parseInputs();

  const actionDirectory = path.join(__dirname, "..");

  const agentDirectory = path.join(actionDirectory, "..", "agent");

  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const pkg = require(`${actionDirectory}/../package.json`);

  await fs.mkdir(logDirectory, { recursive: true });

  const agentLogFilepath = path.join(logDirectory, AGENT_LOG_FILENAME);
  const tetragonLogFilepath = path.join(logDirectory, TETRAGON_LOG_FILENAME);

  installPackages();

  installTetragon({ actionDirectory });

  await startTetragon({
    tetragonLogFilepath,
  });

  await installAgent({
    actionDirectory,
    agentDirectory,
    localAgent,
    version: pkg.version,
    agentDownloadBaseURL,
  });

  await startAgent({
    agentLogFilepath,
    agentDirectory,
    allowedDomains,
    allowedIps,
    dnsPolicy,
    enableSudo,
    egressPolicy,
  });
}

main().catch((error) => {
  console.error(error);
  core.setFailed(error);
  process.exit(1);
});
