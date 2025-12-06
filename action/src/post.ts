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
import { getFileTimestamp } from "./util";

interface WorkflowActionResult {
  workflowRunId: string;
  runAttempt: number;
  jobName?: string; // Human-readable job name
  organization: string;
  repo: string;
  connections: Array<{
    domain?: string;
    ip?: string;
    port?: number;
    blocked: boolean;
    authorized: boolean;
    timestamp: Date;
  }>;
  createdAt: Date;
}

const DECISISONS_LOG_PATH = "/var/log/gha-agent/decisions.log";

function getGitHubContext(): {
  workflowRunId: string;
  runAttempt: number;
  jobName?: string;
  organization: string;
  repo: string;
} {
  const repo = process.env.GITHUB_REPOSITORY || "";
  const [organization] = repo.split("/");
  const workflowRunId = process.env.GITHUB_RUN_ID || "";
  const runAttempt = parseInt(process.env.GITHUB_RUN_ATTEMPT ?? "1")
  const jobName = process.env.GITHUB_JOB || undefined;

  if (!organization || !repo || !workflowRunId) {
    throw new Error(
      "Missing GitHub context: GITHUB_REPOSITORY or GITHUB_RUN_ID not set",
    );
  }

  return { workflowRunId, runAttempt, jobName, organization, repo };
}

async function displaySummary(
  correlatedData: CorrelatedData[],
  controlPlaneBaseUrl?: string,
): Promise<void> {
  const { egressPolicy } = parseInputs();

  const connections = correlatedData.map((data) => ({
    domain: data.domain !== "unknown" ? data.domain : undefined,
    ip: data.destIp !== "unknown" ? data.destIp : undefined,
    port: data.destPort !== "unknown" ? parseInt(data.destPort) : undefined,
    blocked: data.decision === "blocked" && egressPolicy === BLOCK,
    authorized: data.decision === "allowed",
    timestamp: data.ts,
  }));

  const summary = core.summary;

  // Add control plane link if available
  if (controlPlaneBaseUrl) {
    const { workflowRunId } = getGitHubContext();
    const baseUrl = controlPlaneBaseUrl.endsWith("/")
      ? controlPlaneBaseUrl
      : `${controlPlaneBaseUrl}/`;

    summary
      .addHeading("Bullfrog Control Plane", 3)
      .addLink(
        "View detailed results",
        `${baseUrl}workflow-run/${workflowRunId}`,
      );
  } else {
    summary.addHeading("Bullfrog Results", 3);
  }

  // Add connection results table if there are any connections
  if (connections.length > 0) {
    summary.addHeading("Connection Results", 4);

    const tableData = [
      [
        { data: "Timestamp", header: true },
        { data: "Domain", header: true },
        { data: "IP", header: true },
        { data: "Port", header: true },
        { data: "Status", header: true },
      ],
      ...connections.map((conn) => [
        conn.timestamp.toISOString(),
        conn.domain || "-",
        conn.ip || "-",
        conn.port?.toString() || "-",
        conn.blocked
          ? "🚫 Blocked"
          : conn.authorized
            ? "✅ Authorized"
            : "⚠️ Unauthorized",
      ]),
    ];

    summary.addTable(tableData);
  } else {
    summary.addRaw("\n\nNo outbound connections detected.\n");
  }

  await summary.write();
}

async function submitResultsToControlPlane(
  correlatedData: CorrelatedData[],
  apiToken: string,
  controlPlaneBaseUrl: string,
): Promise<void> {
  try {
    const { workflowRunId, runAttempt, jobName, organization, repo } = getGitHubContext();
    const { egressPolicy } = parseInputs();

    const connections = correlatedData.map((data) => ({
      domain: data.domain !== "unknown" ? data.domain : undefined,
      ip: data.destIp !== "unknown" ? data.destIp : undefined,
      port: data.destPort !== "unknown" ? parseInt(data.destPort) : undefined,
      blocked: data.decision === "blocked" && egressPolicy === BLOCK,
      authorized: data.decision === "allowed",
      timestamp: data.ts,
    }));

    const payload: WorkflowActionResult = {
      workflowRunId,
      runAttempt,
      jobName,
      organization,
      repo,
      connections,
      createdAt: new Date(),
    };

    core.debug(
      `Submitting results to control plane: ${JSON.stringify(payload)}`,
    );

    // Ensure the base URL ends with a slash
    const baseUrl = controlPlaneBaseUrl.endsWith("/")
      ? controlPlaneBaseUrl
      : `${controlPlaneBaseUrl}/`;
    const apiUrl = `${baseUrl}api/action/results`;

    const response = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiToken}`,
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `Failed to submit results to control plane: ${response.status} ${response.statusText} - ${errorText}`,
      );
    }

    core.info(
      `Results successfully submitted to control plane for workflow run ${workflowRunId}`,
    );
  } catch (error) {
    core.warning(
      `Failed to submit results to control plane: ${error instanceof Error ? error.message : String(error)}`,
    );
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

    const agentReadyTimestamp = new Date(
      await getFileTimestamp(AGENT_READY_PATH),
    );
    console.log("Agent ready timestamp: ", agentReadyTimestamp);

    const tetragonLogFile = await fs.open(TETRAGON_EVENTS_LOG_PATH);

    const functionsToTrack = ["tcp_connect", "udp_sendmsg"];

    for await (const line of tetragonLogFile.readLines()) {
      const processEntry = JSON.parse(line.trimEnd())?.process_kprobe;

      // Skip entries that are not related to the connect policy
      if (processEntry?.["policy_name"] !== "connect") {
        continue;
      }

      // Skip connection entries that were logged before the agent was ready
      if (new Date(processEntry.process.start_time) < agentReadyTimestamp) {
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
      if (!line.trim()) {
        continue; // Skip empty lines
      }
      const values = line.split("|");
      if (values.length < 4) {
        continue; // Skip malformed lines
      }
      const timestamp = parseInt(values[0], 10);
      if (isNaN(timestamp)) {
        continue; // Skip invalid timestamps
      }

      // Determine if timestamp is in seconds, milliseconds, or nanoseconds
      // If timestamp > 1e12, it's likely in milliseconds or nanoseconds
      // Timestamps in seconds for current dates are around 1.7e9
      let date: Date;
      if (timestamp > 1e15) {
        // Likely nanoseconds, divide by 1e6
        date = new Date(timestamp / 1e6);
      } else if (timestamp > 1e12) {
        // Likely milliseconds
        date = new Date(timestamp);
      } else {
        // Likely seconds
        date = new Date(timestamp * 1000);
      }

      decisions.push({
        ts: date,
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
  const { logDirectory, apiToken, controlPlaneBaseUrl } = parseInputs();
  const agentLogFilepath = path.join(logDirectory, AGENT_LOG_FILENAME);

  await printAgentLogs({ agentLogFilepath });

  try {
    const correlatedData = await getCorrelateData();

    // Always display the summary
    await displaySummary(
      correlatedData,
      apiToken ? controlPlaneBaseUrl : undefined,
    );

    // Submit results to control plane if API token is provided
    if (apiToken) {
      await submitResultsToControlPlane(
        correlatedData,
        apiToken,
        controlPlaneBaseUrl,
      );
    }
  } catch (error) {
    core.warning(
      `Failed to process results: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

main().catch((error) => {
  console.error(error);
  core.setFailed(error);
  process.exit(1);
});
