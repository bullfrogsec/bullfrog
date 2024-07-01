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

// src/post.ts
var core2 = __toESM(require("@actions/core"));
var import_promises = __toESM(require("node:fs/promises"));
var import_node_util = __toESM(require("node:util"));
var import_node_child_process = require("node:child_process");

// src/inputs.ts
var core = __toESM(require("@actions/core"));

// src/constants.ts
var AGENT_LOG_FILENAME = "agent.log";
var CONNECT_LOG_FILENAME = "connect.log";
var AUDIT = "audit";
var BLOCK = "block";
var ALLOWED_DOMAINS_ONLY = "allowed-domains-only";
var ANY = "any";

// src/inputs.ts
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

// src/post.ts
var import_node_path = __toESM(require("node:path"));
var exec = import_node_util.default.promisify(import_node_child_process.exec);
var DECISISONS_LOG_PATH = "/var/log/gha-agent/decisions.log";
async function printAnnotations({
  connectLogFilepath
}) {
  try {
    const correlatedData = await getCorrelateData({ connectLogFilepath });
    const { egressPolicy } = parseInputs();
    const result = egressPolicy === BLOCK ? "Blocked" : "Unauthorized";
    core2.debug("\n\nCorrelated data:\n");
    const annotations = [];
    correlatedData.forEach((data) => {
      core2.debug(JSON.stringify(data));
      if (data.decision !== "blocked") {
        return;
      }
      const time = data.ts.toISOString();
      if (data.domain === "unknown") {
        annotations.push(
          `[${time}] ${result} request to ${data.destIp}:${data.destPort} from processs \`${data.binary} ${data.args}\``
        );
        return;
      } else if (data.destIp === "unknown") {
        annotations.push(
          `[${time}] ${result} DNS request to ${data.domain} from unknown process`
        );
      } else {
        annotations.push(
          `[${time}] ${result} request to ${data.domain} (${data.destIp}:${data.destPort}) from process \`${data.binary} ${data.args}\``
        );
      }
    });
    core2.warning(annotations.join("\n"));
    return;
  } catch (error) {
    core2.debug("No annotations found");
  }
}
async function getOutboundConnections({
  connectLogFilepath
}) {
  try {
    const connections = [];
    await exec(`sudo chmod 644 ${connectLogFilepath}`);
    const log = await import_promises.default.readFile(connectLogFilepath, "utf8");
    const lines = log.split("\n");
    const functionsToTrack = ["tcp_connect"];
    for (const line of lines) {
      if (!line) continue;
      const processEntry = JSON.parse(line).process_kprobe;
      if (!processEntry) continue;
      if (functionsToTrack.includes(processEntry.function_name)) {
        connections.push({
          ts: new Date(processEntry.process.start_time),
          destIp: processEntry.args[0].sock_arg.daddr,
          destPort: processEntry.args[0].sock_arg.dport,
          binary: processEntry.process.binary,
          args: processEntry.process.arguments
        });
      }
    }
    return connections;
  } catch (error) {
    console.error("Error reading log file", error);
    return [];
  }
}
async function getDecisions() {
  try {
    const decisions = [];
    const log = await import_promises.default.readFile(DECISISONS_LOG_PATH, "utf8");
    const lines = log.split("\n");
    for (const line of lines) {
      const values = line.split("|");
      decisions.push({
        ts: new Date(parseInt(values[0]) * 1e3),
        decision: values[1],
        domain: values[2],
        destIp: values[3]
      });
    }
    return decisions;
  } catch (error) {
    console.error("Error reading log file", error);
    return [];
  }
}
async function getCorrelateData({
  connectLogFilepath
}) {
  await new Promise((resolve) => setTimeout(resolve, 5e3));
  const connections = await getOutboundConnections({ connectLogFilepath });
  core2.debug("\n\nConnections:\n");
  connections.forEach((c) => core2.debug(JSON.stringify(c)));
  const decisions = await getDecisions();
  core2.debug("\nDecisions:\n");
  decisions.forEach((d) => core2.debug(JSON.stringify(d)));
  const correlatedData = [];
  for (const connection of connections) {
    let decision = decisions.find(
      (d) => connection.destIp === d.destIp && d.domain !== "unknown"
    );
    if (!decision) {
      decision = decisions.find((d) => connection.destIp === d.destIp);
    }
    correlatedData.push({
      ts: connection.ts,
      decision: decision?.decision ?? "blocked",
      // if we don't have a decision, assume it's blocked because we use an allowlist
      domain: decision?.domain ?? "unknown",
      destIp: connection.destIp,
      destPort: connection.destPort,
      binary: connection.binary,
      args: connection.args
    });
  }
  for (const decision of decisions.filter((d) => d.destIp === "unknown")) {
    correlatedData.push({
      ts: decision.ts,
      decision: decision.decision,
      domain: decision.domain,
      destIp: "unknown",
      destPort: "unknown",
      binary: "unknown",
      args: "unknown"
    });
  }
  return correlatedData;
}
async function printAgentLogs({
  agentLogFilepath
}) {
  try {
    const log = await import_promises.default.readFile(agentLogFilepath, "utf8");
    const lines = log.split("\n");
    for (const line of lines) {
      core2.debug(line);
    }
  } catch (error) {
    console.error("Error reading log file", error);
  }
}
async function _main() {
  const { logDirectory } = parseInputs();
  const connectLogFilepath = import_node_path.default.join(logDirectory, CONNECT_LOG_FILENAME);
  const agentLogFilepath = import_node_path.default.join(logDirectory, AGENT_LOG_FILENAME);
  await printAnnotations({ connectLogFilepath });
  await printAgentLogs({ agentLogFilepath });
}
async function main() {
  try {
    await _main();
  } catch (error) {
    console.error(error);
    core2.setFailed(error);
    process.exit(1);
  }
}
main();
//# sourceMappingURL=post.js.map
