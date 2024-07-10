import * as core from "@actions/core";
import fs from "node:fs/promises";
import { parseInputs } from "./inputs";
import path from "node:path";
import {
  AGENT_LOG_FILENAME,
  AGENT_READY_PATH,
  BLOCK,
  TETRAGON_EVENTS_LOG_PATH,
} from "./constants";
import { getFileTimestamp, waitForFile } from "./util";

const DECISISONS_LOG_PATH = "/var/log/gha-agent/decisions.log";

async function printAnnotations() {
  try {
    const correlatedData = await getCorrelateData();
    const { egressPolicy } = parseInputs();
    const result = egressPolicy === BLOCK ? "Blocked" : "Unauthorized";

    core.debug("\n\nCorrelated data:\n");

    const annotations: string[] = [];

    correlatedData.forEach((data) => {
      core.debug(JSON.stringify(data));
      if (data.decision !== "blocked") {
        return;
      }
      const time = data.ts.toISOString();
      if (data.domain === "unknown") {
        annotations.push(
          `[${time}] ${result} request to ${data.destIp}:${data.destPort} from processs \`${data.binary} ${data.args}\``,
        );
        return;
      } else if (data.destIp === "unknown") {
        annotations.push(
          `[${time}] ${result} DNS request to ${data.domain} from unknown process`,
        );
      } else {
        annotations.push(
          `[${time}] ${result} request to ${data.domain} (${data.destIp}:${data.destPort}) from process \`${data.binary} ${data.args}\``,
        );
      }
    });
    core.warning(annotations.join("\n"));
    return;
  } catch (error) {
    core.debug("No annotations found");
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

async function getOutboundConnections(): Promise<TetragonLog[]> {
  try {
    const connections: TetragonLog[] = [];

    const agentReadyTimestamp = await getFileTimestamp(AGENT_READY_PATH);

    const tetragonLogFile = await fs.open(TETRAGON_EVENTS_LOG_PATH);

    const functionsToTrack = ["tcp_connect"];

    for await (const line of tetragonLogFile.readLines()) {
      const processEntry = JSON.parse(line.trimEnd())?.process_kprobe;

      // Skip entries that are not related to the connect policy
      if (processEntry?.["policy_name"] !== "connect") {
        continue;
      }

      // Skip connection entries that were logged before the agent was ready
      if (processEntry.process.start_time < agentReadyTimestamp) {
        continue;
      }

      // Skip entries that are not related to the functions we are tracking
      if (!functionsToTrack.includes(processEntry.function_name)) {
        continue;
      }

      connections.push({
        ts: new Date(processEntry.process.start_time),
        destIp: processEntry.args[0].sock_arg.daddr,
        destPort: processEntry.args[0].sock_arg.dport,
        binary: processEntry.process.binary,
        args: processEntry.process.arguments,
      });
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

async function getCorrelateData(): Promise<CorrelatedData[]> {
  // give some time for the logs to be written
  await new Promise((resolve) => setTimeout(resolve, 5000));

  const connections = await getOutboundConnections();

  core.debug("\n\nConnections:\n");
  connections.forEach((c) => core.debug(JSON.stringify(c)));

  const decisions = await getDecisions();

  core.debug("\nDecisions:\n");
  decisions.forEach((d) => core.debug(JSON.stringify(d)));

  const correlatedData: CorrelatedData[] = [];

  for (const connection of connections) {
    let decision = decisions.find(
      (d) => connection.destIp === d.destIp && d.domain !== "unknown",
    );
    if (decision === undefined) {
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

async function printAgentLogs({
  agentLogFilepath,
}: {
  agentLogFilepath: string;
}) {
  try {
    const log = await fs.readFile(agentLogFilepath, "utf8");
    const lines = log.split("\n");
    for (const line of lines) {
      core.debug(line);
    }
  } catch (error) {
    console.error("Error reading log file", error);
  }
}

async function main() {
  const { logDirectory } = parseInputs();
  const agentLogFilepath = path.join(logDirectory, AGENT_LOG_FILENAME);

  await printAnnotations();
  await printAgentLogs({ agentLogFilepath });
}

main().catch((error) => {
  console.error(error);
  core.setFailed(error);
  process.exit(1);
});
