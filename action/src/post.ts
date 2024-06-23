import * as core from "@actions/core";
import fs from "node:fs/promises";
import util from "node:util";
import { exec as execCb } from "node:child_process";
import { parseInputs } from "./inputs";
import path from "node:path";
import { BLOCK, CONNECT_LOG_FILENAME } from "./constants";

const exec = util.promisify(execCb);

const DECISISONS_LOG_PATH = "/var/log/gha-agent/decisions.log";

async function printAnnotations({
  connectLogFilepath,
}: {
  connectLogFilepath: string;
}) {
  try {
    const correlatedData = await getCorrelateData({ connectLogFilepath });
    const { egressPolicy } = parseInputs();
    const result = egressPolicy === BLOCK ? "Blocked" : "Unauthorized";

    console.log("\n\nCorrelated data:\n");

    correlatedData.forEach((data) => {
      console.log(JSON.stringify(data));
      if (data.decision !== "blocked") {
        return;
      }
      const time = data.ts.toISOString();
      if (data.domain === "unknown") {
        core.warning(
          `[${time}] ${result} request to ${data.destIp}:${data.destPort} from processs \`${data.binary} ${data.args}\``
        );
        return;
      } else if (data.destIp === "unknown") {
        core.warning(
          `[${time}] ${result} DNS request to ${data.domain} from unknown process`
        );
      } else {
        core.warning(
          `[${time}] ${result} request to ${data.domain} (${data.destIp}:${data.destPort}) from process \`${data.binary} ${data.args}\``
        );
      }
    });
    return;
  } catch (error) {
    console.log("No annotations found");
  }
}

type TetragonLog = {
  ts: Date;
  destIp: string;
  destPort: string;
  binary: string;
  args: string;
};

type Decision = {
  ts: Date;
  decision: "allowed" | "blocked";
  domain: string;
  destIp: string;
};

type CorrelatedData = TetragonLog & Decision;

async function getOutboundConnections({
  connectLogFilepath,
}: {
  connectLogFilepath: string;
}): Promise<TetragonLog[]> {
  try {
    const connections: TetragonLog[] = [];
    // TODO: We shouldn't be using sudo at this point, since we'll probably want to disable sudo early in the action
    await exec(`sudo chmod 644 ${connectLogFilepath}`);
    const log = await fs.readFile(connectLogFilepath, "utf8");
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
          args: processEntry.process.arguments,
        });
      }
    }
    return connections;
  } catch (error) {
    console.error("Error reading log file", error);
    return [];
  }
}

async function getDecisions(): Promise<Decision[]> {
  try {
    const decisions: Decision[] = [];
    const log = await fs.readFile(DECISISONS_LOG_PATH, "utf8");
    const lines = log.split("\n");
    for (const line of lines) {
      const values = line.split("|");
      decisions.push({
        ts: new Date(parseInt(values[0]) * 1000),
        decision: values[1] as "allowed" | "blocked",
        domain: values[2],
        destIp: values[3],
      });
    }
    return decisions;
  } catch (error) {
    console.error("Error reading log file", error);
    return [];
  }
}

async function getCorrelateData({
  connectLogFilepath,
}: {
  connectLogFilepath: string;
}): Promise<CorrelatedData[]> {
  // give some time for the logs to be written
  await new Promise((resolve) => setTimeout(resolve, 5000));

  const connections = await getOutboundConnections({ connectLogFilepath });
  console.log("\n\nConnections:\n");
  connections.forEach((c) => console.log(JSON.stringify(c)));

  const decisions = await getDecisions();
  console.log("\nDecisions:\n");
  decisions.forEach((d) => console.log(JSON.stringify(d)));
  const correlatedData: CorrelatedData[] = [];
  for (const connection of connections) {
    let decision = decisions.find(
      (d) => connection.destIp === d.destIp && d.domain !== "unknown"
    );
    if (!decision) {
      decision = decisions.find((d) => connection.destIp === d.destIp);
    }
    correlatedData.push({
      ts: connection.ts,
      decision: decision?.decision ?? "blocked", // if we don't have a decision, assume it's blocked because we use an allowlist
      domain: decision?.domain ?? "unknown",
      destIp: connection.destIp,
      destPort: connection.destPort,
      binary: connection.binary,
      args: connection.args,
    });
  }
  // Add any decisions that don't have a corresponding connection (blocked DNS queries)
  for (const decision of decisions.filter((d) => d.destIp === "unknown")) {
    correlatedData.push({
      ts: decision.ts,
      decision: decision.decision,
      domain: decision.domain,
      destIp: "unknown",
      destPort: "unknown",
      binary: "unknown",
      args: "unknown",
    });
  }
  return correlatedData;
}

async function _main() {
  const { logDirectory } = parseInputs();
  const connectLogFilepath = path.join(logDirectory, CONNECT_LOG_FILENAME);

  await printAnnotations({ connectLogFilepath });
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
