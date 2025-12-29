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
    protocol: string;
    reason: string;
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

// Map reason codes to human-friendly descriptions
const REASON_CODE_MAP: Record<string, string> = {
  "domain-allowed": "Domain allowed",
  "domain-not-allowed": "Domain not allowed",
  "dns-resolved": "DNS resolved",
  "ip-allowed": "IP allowed",
  "ip-not-allowed": "IP not allowed",
  "untrusted-dns-server": "Untrusted DNS server",
  "no-network-layer": "No network layer",
  "unknown-network-layer": "Unknown network layer",
};

function getHumanFriendlyReason(reasonCode: string): string {
  return REASON_CODE_MAP[reasonCode] || reasonCode;
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
        { data: "Protocol", header: true },
        { data: "Reason", header: true },
        { data: "Status", header: true },
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
  protocol: string;
  reason: string;
};

async function getConnections(): Promise<Connection[]> {
  // give some time for the logs to be written
  await new Promise((resolve) => setTimeout(resolve, 5000));

  try {
    const allConnections: Connection[] = [];
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
      const protocol = values[2];
      const destIp = values[4];
      const destPort = values[5];
      const domain = values[6];
      const reason = values[7];

      allConnections.push({
        timestamp: date,
        domain: domain !== "unknown" ? domain : undefined,
        ip: destIp !== "unknown" ? destIp : undefined,
        port: destPort !== "unknown" ? parseInt(destPort) : undefined,
        blocked: decision === "blocked" && egressPolicy === BLOCK,
        authorized: decision === "allowed",
        protocol,
        reason,
      });
    }

    // Filter DNS noise according to logic:
    // 1. If a non-DNS connection with reason "ip-allowed" exists for a domain,
    //    exclude "dns-resolved" and "domain-allowed" for that domain
    // 2. If only "dns-resolved" connections exist, deduplicate by domain+IP
    // 3. If only "domain-allowed" connections exist, deduplicate by domain
    const filtered = filterDNSNoise(allConnections);

    core.debug("\n\nConnections:\n");
    filtered.forEach((c) => core.debug(JSON.stringify(c)));

    return filtered;
  } catch (error) {
    console.error("Error reading connections log file", error);
    return [];
  }
}

function filterDNSNoise(connections: Connection[]): Connection[] {
  // Group connections by domain
  const byDomain = new Map<string, Connection[]>();

  for (const conn of connections) {
    const domain = conn.domain || "unknown";
    if (!byDomain.has(domain)) {
      byDomain.set(domain, []);
    }
    byDomain.get(domain)!.push(conn);
  }

  const result: Connection[] = [];

  for (const [, conns] of byDomain) {
    // Check if there are any non-DNS connections with reason "ip-allowed"
    const hasActualConnection = conns.some(
      (c) =>
        !["DNS", "DNS-response"].includes(c.protocol) &&
        c.reason === "ip-allowed",
    );

    if (hasActualConnection) {
      // Exclude DNS-related logs (domain-allowed and dns-resolved)
      const filtered = conns.filter(
        (c) => c.reason !== "domain-allowed" && c.reason !== "dns-resolved",
      );
      result.push(...filtered);
    } else {
      const hasDnsResolved = conns.some((c) => c.reason === "dns-resolved");

      if (hasDnsResolved) {
        // Has DNS responses but no actual connection
        // Show only dns-resolved entries, deduplicated by domain+IP
        const dnsResolvedOnly = conns.filter(
          (c) => c.reason === "dns-resolved",
        );
        const deduplicated = deduplicateByDomainAndIP(dnsResolvedOnly);
        result.push(...deduplicated);
      } else {
        const hasOnlyDomainAllowed = conns.every(
          (c) => c.reason === "domain-allowed",
        );

        if (hasOnlyDomainAllowed) {
          // Only DNS queries (no response) - deduplicate by domain
          const deduplicated = deduplicateByDomain(conns);
          result.push(...deduplicated);
        } else {
          // Other cases (blocked, untrusted-dns-server, etc.)
          // For blocked entries, also deduplicate to reduce noise
          const isBlocked = conns.some((c) => c.blocked);
          if (isBlocked) {
            // Deduplicate blocked entries by domain
            const deduplicated = deduplicateByDomain(conns);
            result.push(...deduplicated);
          } else {
            // Include all other entries
            result.push(...conns);
          }
        }
      }
    }
  }

  return result;
}

function deduplicateByDomain(connections: Connection[]): Connection[] {
  const seen = new Set<string>();
  const result: Connection[] = [];

  // Sort by timestamp to keep the first occurrence
  const sorted = [...connections].sort(
    (a, b) => a.timestamp.getTime() - b.timestamp.getTime(),
  );

  for (const conn of sorted) {
    const key = conn.domain || "unknown";
    if (!seen.has(key)) {
      seen.add(key);
      result.push(conn);
    }
  }

  return result;
}

function deduplicateByDomainAndIP(connections: Connection[]): Connection[] {
  const seen = new Set<string>();
  const result: Connection[] = [];

  // Sort by timestamp to keep the first occurrence
  const sorted = [...connections].sort(
    (a, b) => a.timestamp.getTime() - b.timestamp.getTime(),
  );

  for (const conn of sorted) {
    const key = `${conn.domain || "unknown"}|${conn.ip || "unknown"}`;
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
