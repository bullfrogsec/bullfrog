import * as core from "@actions/core";
import fs from "node:fs/promises";
import { parseInputs } from "./inputs";
import path from "node:path";
import { AGENT_LOG_FILENAME, CONNECTIONS_LOG_PATH, BLOCK } from "./constants";
import { getDate } from "./util";

// Map reason codes to human-friendly descriptions
const REASON_CODE_MAP: Record<string, string> = {
  "domain-allowed": "Domain allowed",
  "domain-not-allowed": "Domain not allowed",
  "ip-allowed": "IP allowed",
  "ip-not-allowed": "IP not allowed",
  "untrusted-dns-server": "Untrusted DNS server",
  "no-network-layer": "No network layer",
  "unknown-network-layer": "Unknown network layer",
};

type DockerInfo = {
  containerImage: string;
  containerName: string;
};

export type Connection = {
  timestamp: Date;
  domain?: string;
  ip?: string;
  port?: number;
  blocked: boolean;
  authorized: boolean;
  protocol: string;
  reason: string;
  process?: string;
  exePath?: string;
  commandLine?: string;
  docker?: DockerInfo;
};

interface WorkflowJobConnectionResults {
  workflowRunId: string;
  runAttempt: number;
  jobName?: string; // Human-readable job name
  organization: string;
  repo: string;
  connections: Array<Connection>;
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

export function getHumanFriendlyReason(reasonCode: string): string {
  return REASON_CODE_MAP[reasonCode] || reasonCode;
}

export async function displaySummary(
  connections: Connection[],
  controlPlaneWebappBaseUrl?: string,
  workflowRunId?: string,
  runAttempt?: number,
): Promise<void> {
  const summary = core.summary;

  if (controlPlaneWebappBaseUrl && workflowRunId) {
    let url = `${controlPlaneWebappBaseUrl}workflow-run/${workflowRunId}`;
    if (runAttempt && runAttempt >= 2) {
      url += `?attempt=${runAttempt}`;
    }
    summary
      .addHeading("Bullfrog Control Plane", 3)
      .addLink("View detailed results", url);
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
        { data: "Protocol", header: true },
        { data: "Reason", header: true },
        { data: "Status", header: true },
        { data: "Process", header: true },
        { data: "Container", header: true },
        { data: "Exe Path", header: true },
        { data: "Command Line", header: true },
      ],
      ...connections.map((conn) => [
        conn.timestamp.toISOString(),
        conn.domain || "-",
        conn.ip || "-",
        conn.port?.toString() || "-",
        conn.protocol,
        getHumanFriendlyReason(conn.reason),
        conn.blocked
          ? "🚫 Blocked"
          : conn.authorized
            ? "✅ Authorized"
            : "⚠️ Unauthorized",
        conn.process || "-",
        conn.docker
          ? `${conn.docker.containerImage}:${conn.docker.containerName}`
          : "-",
        conn.exePath || "-",
        conn.commandLine || "-",
      ]),
    ];

    summary.addTable(tableData);
  } else {
    summary.addRaw("\n\nNo outbound connections detected.\n");
  }

  await summary.write();
}

export async function getConnections(): Promise<{
  filtered: Connection[];
  raw: Connection[];
}> {
  // give some time for the logs to be written
  await new Promise((resolve) => setTimeout(resolve, 5000));

  try {
    const allConnections: Connection[] = [];
    const { egressPolicy } = parseInputs();
    const log = await fs.readFile(CONNECTIONS_LOG_PATH, "utf8");
    const lines = log.split("\n");
    core.debug("\n\nConnections.log:\n");
    lines.forEach((l) => core.debug(l));

    for (const line of lines) {
      if (!line.trim()) {
        continue; // Skip empty lines
      }

      try {
        // Parse JSON log entry
        const logEntry = JSON.parse(line);

        const timestamp = parseInt(logEntry.timestamp, 10);
        if (isNaN(timestamp)) {
          continue; // Skip invalid timestamps
        }

        const date = getDate(timestamp);

        const decision = logEntry.decision as "allowed" | "blocked";
        const protocol = logEntry.protocol;
        const destIp = logEntry.dstIP;
        const destPort = logEntry.dstPort;
        const domain = logEntry.domain;
        const reason = logEntry.reason;
        const process = logEntry.processName;
        const commandLine = logEntry.commandLine;
        const exePath = logEntry.executablePath;
        const docker = logEntry.docker;

        allConnections.push({
          timestamp: date,
          domain: domain !== "unknown" ? domain : undefined,
          ip: destIp !== "unknown" ? destIp : undefined,
          port: destPort !== "unknown" ? parseInt(destPort) : undefined,
          blocked: decision === "blocked" && egressPolicy === BLOCK,
          authorized: decision === "allowed",
          protocol,
          reason,
          process: process !== "unknown" ? process : undefined,
          exePath: exePath !== "unknown" ? exePath : undefined,
          commandLine: commandLine !== "unknown" ? commandLine : undefined,
          docker: docker || undefined,
        });
      } catch {
        core.warning(`Failed to parse log line: ${line}`);
        continue;
      }
    }

    // Deduplicate connections by domain+ip+process+docker
    const filtered = filterConnectionsNoise(allConnections);

    core.debug("\n\nConnections:\n");
    filtered.forEach((c) => core.debug(JSON.stringify(c)));

    return { filtered, raw: allConnections };
  } catch (error) {
    console.error("Error reading connections log file", error);
    return { filtered: [], raw: [] };
  }
}

function getProcessKey(conn: Connection): string {
  // Create a unique key for process identification using all available process info
  const process = conn.process || "unknown-process";
  const exePath = conn.exePath || "unknown-exePath";
  const commandLine = conn.commandLine || "unknown-commandLine";
  return `${process}|${exePath}|${commandLine}`;
}

function getDockerKey(conn: Connection): string {
  // Create a unique key for docker container identification
  if (conn.docker) {
    return `${conn.docker.containerImage}:${conn.docker.containerName}`;
  }
  return "no-docker";
}

export function filterConnectionsNoise(
  connections: Connection[],
): Connection[] {
  const seen = new Set<string>();
  const result: Connection[] = [];

  // Sort by timestamp to keep the first occurrence
  const sorted = [...connections].sort(
    (a, b) => a.timestamp.getTime() - b.timestamp.getTime(),
  );

  for (const conn of sorted) {
    // Create deduplication key from domain+ip+process+docker
    const domain = conn.domain || "unknown";
    const ip = conn.ip || "unknown";
    const processKey = getProcessKey(conn);
    const dockerKey = getDockerKey(conn);
    const key = `${domain}|${ip}|${processKey}|${dockerKey}`;

    if (!seen.has(key)) {
      seen.add(key);
      result.push(conn);
    }
  }

  return result;
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

export async function submitResultsToControlPlane(
  connections: Connection[],
  apiToken: string,
  controlPlaneApiBaseUrl: string,
): Promise<void> {
  try {
    const { workflowRunId, runAttempt, jobName, organization, repo } =
      getGitHubContext();

    const payload: WorkflowJobConnectionResults = {
      workflowRunId,
      runAttempt,
      jobName,
      organization,
      repo,
      connections,
    };

    core.debug(
      `Submitting results to control plane: ${JSON.stringify(payload)}`,
    );

    const apiUrl = `${controlPlaneApiBaseUrl}v1/events`;

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

async function main() {
  const {
    logDirectory,
    apiToken,
    controlPlaneApiBaseUrl,
    controlPlaneWebappBaseUrl,
  } = parseInputs();
  const agentLogFilepath = path.join(logDirectory, AGENT_LOG_FILENAME);

  await printAgentLogs({ agentLogFilepath });

  try {
    const { filtered, raw } = await getConnections();

    const shouldAddControlPlaneResultsUrl =
      apiToken && controlPlaneWebappBaseUrl;

    const { workflowRunId, runAttempt } = getGitHubContext();

    await displaySummary(
      filtered,
      shouldAddControlPlaneResultsUrl ? controlPlaneWebappBaseUrl : undefined,
      workflowRunId,
      runAttempt,
    );

    // Submit results to control plane if API token is provided
    if (apiToken && controlPlaneApiBaseUrl) {
      await submitResultsToControlPlane(raw, apiToken, controlPlaneApiBaseUrl);
    }
  } catch (error) {
    core.warning(
      `Failed to process results: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

// Only run main if this file is executed directly (not imported for tests)
if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    core.setFailed(error);
    process.exit(1);
  });
}
