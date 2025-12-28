import * as core from "@actions/core";
import fs from "node:fs/promises";
import { parseInputs } from "./inputs";
import path from "node:path";
import { AGENT_LOG_FILENAME, CONNECTIONS_LOG_PATH, BLOCK } from "./constants";

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
  const runAttempt = parseInt(process.env.GITHUB_RUN_ATTEMPT ?? "1");
  const jobName = process.env.GITHUB_JOB || undefined;

  if (!organization || !repo || !workflowRunId) {
    throw new Error(
      "Missing GitHub context: GITHUB_REPOSITORY or GITHUB_RUN_ID not set",
    );
  }

  return { workflowRunId, runAttempt, jobName, organization, repo };
}

async function displaySummary(
  connections: Connection[],
  controlPlaneBaseUrl?: string,
): Promise<void> {
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
  connections: Connection[],
  apiToken: string,
  controlPlaneBaseUrl: string,
): Promise<void> {
  try {
    const { workflowRunId, runAttempt, jobName, organization, repo } =
      getGitHubContext();

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
    const apiUrl = `${baseUrl}v1/events`;

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

type Connection = {
  timestamp: Date;
  domain?: string;
  ip?: string;
  port?: number;
  blocked: boolean;
  authorized: boolean;
};

async function getConnections(): Promise<Connection[]> {
  // give some time for the logs to be written
  await new Promise((resolve) => setTimeout(resolve, 5000));

  try {
    const connections: Connection[] = [];
    const { egressPolicy } = parseInputs();
    const log = await fs.readFile(CONNECTIONS_LOG_PATH, "utf8");
    const lines = log.split("\n");

    for (const line of lines) {
      if (!line.trim()) {
        continue; // Skip empty lines
      }

      // connections.log format: timestamp|decision|protocol|srcIP|dstIP|dstPort|domain|reason
      const values = line.split("|");
      if (values.length < 8) {
        continue; // Skip malformed lines
      }

      const timestamp = parseInt(values[0], 10);
      if (isNaN(timestamp)) {
        continue; // Skip invalid timestamps
      }

      // Determine if timestamp is in seconds, milliseconds, or nanoseconds
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

      const decision = values[1] as "allowed" | "blocked";
      const destIp = values[4];
      const destPort = values[5];
      const domain = values[6];

      connections.push({
        timestamp: date,
        domain: domain !== "unknown" ? domain : undefined,
        ip: destIp !== "unknown" ? destIp : undefined,
        port: destPort !== "unknown" ? parseInt(destPort) : undefined,
        blocked: decision === "blocked" && egressPolicy === BLOCK,
        authorized: decision === "allowed",
      });
    }

    core.debug("\n\nConnections:\n");
    connections.forEach((c) => core.debug(JSON.stringify(c)));

    return connections;
  } catch (error) {
    console.error("Error reading connections log file", error);
    return [];
  }
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
    const connections = await getConnections();

    // Always display the summary
    await displaySummary(
      connections,
      apiToken ? controlPlaneBaseUrl : undefined,
    );

    // Submit results to control plane if API token is provided
    if (apiToken) {
      await submitResultsToControlPlane(
        connections,
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
