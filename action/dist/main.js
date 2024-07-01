"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/main.ts
var core3 = __toESM(require("@actions/core"));
var import_promises3 = __toESM(require("node:fs/promises"));
var import_node_util = __toESM(require("node:util"));
var import_node_child_process = require("node:child_process");
var import_node_path = __toESM(require("node:path"));

// src/constants.ts
var AGENT_LOG_FILENAME = "agent.log";
var CONNECT_LOG_FILENAME = "connect.log";
var TETRAGON_LOG_FILENAME = "tetragon.log";
var TETRAGON_EVENTS_LOG_PATH = "/var/log/tetragon/tetragon.log";
var AGENT_INSTALL_PATH = "/opt/bullfrog/agent";
var AGENT_READY_PATH = "/var/run/bullfrog/agent-ready";
var AUDIT = "audit";
var BLOCK = "block";
var ALLOWED_DOMAINS_ONLY = "allowed-domains-only";
var ANY = "any";

// src/inputs.ts
var core = __toESM(require("@actions/core"));
function parseInputs() {
  const rawAllowedIps = core.getInput("allowed-ips");
  const allowedIps = rawAllowedIps.length !== 0 ? rawAllowedIps.split("\n") : [];
  const rawAllowedDomains = core.getInput("allowed-domains");
  const allowedDomains = rawAllowedDomains.length !== 0 ? rawAllowedDomains.split("\n") : [];
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
    localAgentPath: core.getInput("local-agent-path"),
    agentDownloadBaseURL: core.getInput("agent-download-base-url")
  };
}

// src/util.ts
var core2 = __toESM(require("@actions/core"));
var import_promises = __toESM(require("node:fs/promises"));
var import_promises2 = require("node:timers/promises");
async function waitForFile(filePath, timeout = 15e3, interval = 500) {
  const startTime = Date.now();
  while (Date.now() - startTime < timeout) {
    try {
      await import_promises.default.access(filePath);
      core2.debug(`File ${filePath} is available!`);
      return true;
    } catch (err) {
      await (0, import_promises2.setTimeout)(interval);
    }
  }
  core2.debug(`Timeout: File ${filePath} is not available.`);
  return false;
}

// src/main.ts
var exec = import_node_util.default.promisify(import_node_child_process.exec);
function installPackages() {
  console.log("Installing packages");
  const { status } = (0, import_node_child_process.spawnSync)(
    "sudo",
    ["apt-get", "install", "-y", "libnetfilter-queue-dev", "nftables"],
    { stdio: "inherit" }
  );
  if (status !== 0) {
    throw new Error("Couldn't install packages");
  }
}
function installTetragon({ actionDirectory }) {
  console.log("Installing Tetragon");
  const { status } = (0, import_node_child_process.spawnSync)(
    "bash",
    [import_node_path.default.join(actionDirectory, "scripts", "install_tetragon.sh")],
    {
      stdio: "inherit",
      env: {
        TETRAGON_POLICIES_DIRECTORY: import_node_path.default.join(actionDirectory, "tetragon")
      }
    }
  );
  if (status !== 0) {
    throw new Error("Couldn't install Tetragon");
  }
}
async function startTetragon({
  connectLogFilepath,
  tetragonLogFilepath
}) {
  const out = (await import_promises3.default.open(tetragonLogFilepath, "a")).fd;
  core3.debug("Starting Tetragon");
  console.time("Tetragon startup time");
  (0, import_node_child_process.spawn)("sudo", ["tetragon"], {
    stdio: ["ignore", out, out],
    detached: true
  }).unref();
  const tetragonReady = await waitForFile(TETRAGON_EVENTS_LOG_PATH);
  if (!tetragonReady) {
    throw new Error("Tetragon could not start");
  }
  console.timeEnd("Tetragon startup time");
  const connectOut = (await import_promises3.default.open(connectLogFilepath, "a")).fd;
  (0, import_node_child_process.spawn)(
    `sudo tail -n +1 -F ${TETRAGON_EVENTS_LOG_PATH} | jq -c --unbuffered 'select(.process_kprobe.policy_name == "connect")'`,
    {
      shell: true,
      stdio: ["ignore", connectOut, "ignore"],
      detached: true
    }
  ).unref();
}
async function downloadAgent({
  actionDirectory,
  localAgentPath,
  version,
  agentDownloadBaseURL
}) {
  if (localAgentPath !== "") {
    const absolutePath = import_node_path.default.join(actionDirectory, "..", localAgentPath);
    core3.debug(`Using local agent from ${absolutePath}`);
    return absolutePath;
  }
  console.log(`Downloading agent v${version}`);
  const { status } = (0, import_node_child_process.spawnSync)(
    "bash",
    [
      import_node_path.default.join(actionDirectory, "scripts", "download_agent.sh"),
      `v${version}`,
      agentDownloadBaseURL
    ],
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
  agentPath
}) {
  const blockingMode = egressPolicy === BLOCK;
  console.log("Loading nftables rules");
  if (blockingMode && dnsPolicy === ALLOWED_DOMAINS_ONLY) {
    await exec(
      `sudo nft -f ${import_node_path.default.join(agentDirectory, "queue_block_with_dns.nft")}`
    );
    console.log("loaded blocking rules (with DNS)");
  } else if (blockingMode) {
    await exec(`sudo nft -f ${import_node_path.default.join(agentDirectory, "queue_block.nft")}`);
    console.log("loaded blocking rules");
  } else {
    await exec(`sudo nft -f ${import_node_path.default.join(agentDirectory, "queue_audit.nft")}`);
    console.log("loaded audit rules");
  }
  const agentOut = (await import_promises3.default.open(agentLogFilepath, "a")).fd;
  console.log(`Starting agent from ${agentPath}`);
  console.time("Agent startup time");
  await exec(`sudo chmod +x ${agentPath}`);
  (0, import_node_child_process.spawn)(
    "sudo",
    [agentPath, "--dns-policy", dnsPolicy, "--egress-policy", egressPolicy],
    {
      stdio: ["ignore", agentOut, agentOut],
      detached: true
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
    agentDownloadBaseURL
  } = parseInputs();
  const actionDirectory = import_node_path.default.join(__dirname, "..");
  const agentDirectory = import_node_path.default.join(actionDirectory, "..", "agent");
  const pkg = require(`${actionDirectory}/../package.json`);
  await import_promises3.default.mkdir(logDirectory, { recursive: true });
  if (allowedDomains.length !== 0) {
    await import_promises3.default.writeFile("allowed_domains.txt", allowedDomains.join("\n"));
  }
  if (allowedIps.length !== 0) {
    await import_promises3.default.writeFile("allowed_ips.txt", allowedIps.join("\n"));
  }
  const agentLogFilepath = import_node_path.default.join(logDirectory, AGENT_LOG_FILENAME);
  const connectLogFilepath = import_node_path.default.join(logDirectory, CONNECT_LOG_FILENAME);
  const tetragonLogFilepath = import_node_path.default.join(logDirectory, TETRAGON_LOG_FILENAME);
  installPackages();
  installTetragon({ actionDirectory });
  await startTetragon({
    connectLogFilepath,
    tetragonLogFilepath
  });
  const agentPath = await downloadAgent({
    actionDirectory,
    localAgentPath,
    version: pkg.version,
    agentDownloadBaseURL
  });
  await startAgent({
    agentDirectory,
    dnsPolicy,
    egressPolicy,
    agentLogFilepath,
    agentPath
  });
}
async function main() {
  try {
    await _main();
  } catch (error) {
    console.error(error);
    core3.setFailed(error);
    process.exit(1);
  }
}
main();
//# sourceMappingURL=main.js.map
