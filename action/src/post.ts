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
  jobName?: string;
  organization: string;
  repo: string;
} {
  const repo = process.env.GITHUB_REPOSITORY || "";
  const [organization] = repo.split("/");
  const workflowRunId = process.env.GITHUB_RUN_ID || "";
  const jobName = process.env.GITHUB_JOB || undefined;

  if (!organization || !repo || !workflowRunId) {
    throw new Error(
      "Missing GitHub context: GITHUB_REPOSITORY or GITHUB_RUN_ID not set",
    );
  }

  return { workflowRunId, jobName, organization, repo };
}

async function submitResultsToControlPlane(
  correlatedData: CorrelatedData[],
  apiToken: string,
  controlPlaneBaseUrl: string,
): Promise<void> {
  try {
    const { workflowRunId, jobName, organization, repo } = getGitHubContext();
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

    // Add a link to the control plane workflow run in the summary
    await core.summary
      .addHeading("Bullfrog Control Plane", 3)
      .addLink(
        "View detailed results",
        `${baseUrl}workflow-run/${workflowRunId}`,
      )
      .write();
  } catch (error) {
    core.warning(
      `Failed to submit results to control plane: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

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
  } catch {
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
  const { logDirectory, apiToken, controlPlaneBaseUrl } = parseInputs();
  const agentLogFilepath = path.join(logDirectory, AGENT_LOG_FILENAME);

  await printAnnotations();
  await printAgentLogs({ agentLogFilepath });

  // Submit results to control plane if API token is provided
  if (apiToken) {
    try {
      const correlatedData = await getCorrelateData();
      await submitResultsToControlPlane(
        correlatedData,
        apiToken,
        controlPlaneBaseUrl,
      );
    } catch (error) {
      core.warning(
        `Failed to submit results to control plane: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
}

main().catch((error) => {
  console.error(error);
  core.setFailed(error);
  process.exit(1);
});
