import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  getHumanFriendlyReason,
  filterConnectionsNoise,
  type Connection,
  displaySummary,
  getConnections,
  submitResultsToControlPlane,
} from "../post";
import * as core from "@actions/core";
import * as fs from "node:fs/promises";

vi.mock("@actions/core");
vi.mock("node:fs/promises");
vi.mock("../inputs");

describe("post", () => {
  describe("getHumanFriendlyReason", () => {
    it("should map known reason codes to human-friendly descriptions", () => {
      expect(getHumanFriendlyReason("domain-allowed")).toBe("Domain allowed");
      expect(getHumanFriendlyReason("domain-not-allowed")).toBe(
        "Domain not allowed",
      );
      expect(getHumanFriendlyReason("ip-allowed")).toBe("IP allowed");
      expect(getHumanFriendlyReason("ip-not-allowed")).toBe("IP not allowed");
      expect(getHumanFriendlyReason("untrusted-dns-server")).toBe(
        "Untrusted DNS server",
      );
      expect(getHumanFriendlyReason("no-network-layer")).toBe(
        "No network layer",
      );
      expect(getHumanFriendlyReason("unknown-network-layer")).toBe(
        "Unknown network layer",
      );
    });

    it("should return the original code for unknown reason codes", () => {
      expect(getHumanFriendlyReason("unknown-reason")).toBe("unknown-reason");
      expect(getHumanFriendlyReason("custom-code")).toBe("custom-code");
      expect(getHumanFriendlyReason("")).toBe("");
    });
  });

  describe("filterConnectionsNoise", () => {
    it("should deduplicate by domain+ip+process+docker - same everything", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:02Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
      ];

      const result = filterConnectionsNoise(connections);

      // Should keep only the first one (earliest timestamp)
      expect(result).toHaveLength(1);
      expect(result[0].timestamp).toEqual(new Date("2024-01-01T00:00:00Z"));
    });

    it("should NOT deduplicate when process is different", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "wget",
        },
      ];

      const result = filterConnectionsNoise(connections);

      expect(result).toHaveLength(2);
      expect(result[0].process).toBe("curl");
      expect(result[1].process).toBe("wget");
    });

    it("should NOT deduplicate when docker container is different", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          docker: {
            containerImage: "nginx",
            containerName: "web1",
          },
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          docker: {
            containerImage: "nginx",
            containerName: "web2",
          },
        },
      ];

      const result = filterConnectionsNoise(connections);

      expect(result).toHaveLength(2);
      expect(result[0].docker?.containerName).toBe("web1");
      expect(result[1].docker?.containerName).toBe("web2");
    });

    it("should NOT deduplicate when IP is different", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.35",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
      ];

      const result = filterConnectionsNoise(connections);

      expect(result).toHaveLength(2);
      expect(result[0].ip).toBe("93.184.216.34");
      expect(result[1].ip).toBe("93.184.216.35");
    });

    it("should NOT deduplicate when domain is different", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "google.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
      ];

      const result = filterConnectionsNoise(connections);

      expect(result).toHaveLength(2);
      expect(result[0].domain).toBe("example.com");
      expect(result[1].domain).toBe("google.com");
    });

    it("should keep DNS connections even when TCP connections exist for same domain", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "api.github.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "api.github.com",
          ip: "140.82.121.6",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
      ];

      const result = filterConnectionsNoise(connections);

      // Should keep both DNS and TCP connections
      expect(result).toHaveLength(2);
      expect(result[0].protocol).toBe("DNS");
      expect(result[1].protocol).toBe("TCP");
    });

    it("should deduplicate multiple DNS queries to same domain by same process", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:02Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
          process: "curl",
        },
      ];

      const result = filterConnectionsNoise(connections);

      // Should keep only the first occurrence (DNS has no IP, so dedup by domain+process+docker)
      expect(result).toHaveLength(1);
      expect(result[0].timestamp).toEqual(new Date("2024-01-01T00:00:00Z"));
    });

    it("should NOT deduplicate DNS queries from different processes", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
          process: "wget",
        },
      ];

      const result = filterConnectionsNoise(connections);

      expect(result).toHaveLength(2);
      expect(result[0].process).toBe("curl");
      expect(result[1].process).toBe("wget");
    });

    it("should handle undefined process/exePath/commandLine consistently", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: undefined,
          exePath: undefined,
          commandLine: undefined,
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: undefined,
          exePath: undefined,
          commandLine: undefined,
        },
      ];

      const result = filterConnectionsNoise(connections);

      // Should deduplicate since all fields are the same
      expect(result).toHaveLength(1);
    });

    it("should handle undefined docker consistently", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          docker: undefined,
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          docker: undefined,
        },
      ];

      const result = filterConnectionsNoise(connections);

      // Should deduplicate since all fields are the same
      expect(result).toHaveLength(1);
    });

    it("should handle empty connections array", () => {
      const result = filterConnectionsNoise([]);
      expect(result).toEqual([]);
    });

    it("should handle mixed scenario with multiple processes and containers", () => {
      const connections: Connection[] = [
        // curl to example.com
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
        // wget to example.com
        {
          timestamp: new Date("2024-01-01T00:00:02Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
          process: "wget",
        },
        {
          timestamp: new Date("2024-01-01T00:00:03Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "wget",
        },
        // docker container web1 to example.com
        {
          timestamp: new Date("2024-01-01T00:00:04Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
          docker: {
            containerImage: "nginx",
            containerName: "web1",
          },
        },
        {
          timestamp: new Date("2024-01-01T00:00:05Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          docker: {
            containerImage: "nginx",
            containerName: "web1",
          },
        },
      ];

      const result = filterConnectionsNoise(connections);

      // Should have 6 entries: DNS+TCP for curl, DNS+TCP for wget, DNS+TCP for web1
      expect(result).toHaveLength(6);

      const curlConns = result.filter((c) => c.process === "curl");
      expect(curlConns).toHaveLength(2);

      const wgetConns = result.filter((c) => c.process === "wget");
      expect(wgetConns).toHaveLength(2);

      const dockerConns = result.filter(
        (c) => c.docker?.containerName === "web1",
      );
      expect(dockerConns).toHaveLength(2);
    });

    it("should NOT deduplicate when exePath is different", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "python",
          exePath: "/usr/bin/python3",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "python",
          exePath: "/usr/local/bin/python3",
        },
      ];

      const result = filterConnectionsNoise(connections);

      expect(result).toHaveLength(2);
      expect(result[0].exePath).toBe("/usr/bin/python3");
      expect(result[1].exePath).toBe("/usr/local/bin/python3");
    });

    it("should NOT deduplicate when commandLine is different", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
          commandLine: "curl https://example.com",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
          commandLine: "curl https://example.com/api",
        },
      ];

      const result = filterConnectionsNoise(connections);

      expect(result).toHaveLength(2);
      expect(result[0].commandLine).toBe("curl https://example.com");
      expect(result[1].commandLine).toBe("curl https://example.com/api");
    });

    it("should deduplicate multiple blocked connections to same domain by same process", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "malicious.com",
          ip: "1.2.3.4",
          blocked: true,
          authorized: false,
          protocol: "TCP",
          reason: "domain-not-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "malicious.com",
          ip: "1.2.3.4",
          blocked: true,
          authorized: false,
          protocol: "TCP",
          reason: "domain-not-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:02Z"),
          domain: "malicious.com",
          ip: "1.2.3.4",
          blocked: true,
          authorized: false,
          protocol: "TCP",
          reason: "domain-not-allowed",
          process: "curl",
        },
      ];

      const result = filterConnectionsNoise(connections);

      // Should keep only the first blocked connection
      expect(result).toHaveLength(1);
      expect(result[0].timestamp).toEqual(new Date("2024-01-01T00:00:00Z"));
      expect(result[0].blocked).toBe(true);
    });

    it("should NOT deduplicate blocked connections from different processes", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "malicious.com",
          ip: "1.2.3.4",
          blocked: true,
          authorized: false,
          protocol: "TCP",
          reason: "domain-not-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "malicious.com",
          ip: "1.2.3.4",
          blocked: true,
          authorized: false,
          protocol: "TCP",
          reason: "domain-not-allowed",
          process: "wget",
        },
      ];

      const result = filterConnectionsNoise(connections);

      expect(result).toHaveLength(2);
      expect(result[0].process).toBe("curl");
      expect(result[1].process).toBe("wget");
    });

    it("should keep both allowed and blocked connections to same domain", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "1.2.3.4",
          blocked: true,
          authorized: false,
          protocol: "TCP",
          reason: "ip-not-allowed",
          process: "curl",
        },
      ];

      const result = filterConnectionsNoise(connections);

      // Different IPs, so should keep both
      expect(result).toHaveLength(2);
      expect(result[0].blocked).toBe(false);
      expect(result[1].blocked).toBe(true);
    });

    it("should deduplicate blocked DNS queries", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "malicious.com",
          blocked: true,
          authorized: false,
          protocol: "DNS",
          reason: "domain-not-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "malicious.com",
          blocked: true,
          authorized: false,
          protocol: "DNS",
          reason: "domain-not-allowed",
          process: "curl",
        },
      ];

      const result = filterConnectionsNoise(connections);

      // Same domain, no IP (DNS), same process -> deduplicate
      expect(result).toHaveLength(1);
      expect(result[0].protocol).toBe("DNS");
    });
  });

  describe("displaySummary", () => {
    let originalEnv: NodeJS.ProcessEnv;

    beforeEach(() => {
      originalEnv = { ...process.env };
      process.env.GITHUB_REPOSITORY = "test-org/test-repo";
      process.env.GITHUB_RUN_ID = "12345";
      process.env.GITHUB_RUN_ATTEMPT = "1";
      process.env.GITHUB_JOB = "test-job";

      vi.clearAllMocks();

      // Mock core.summary methods
      const mockSummary = {
        addHeading: vi.fn().mockReturnThis(),
        addLink: vi.fn().mockReturnThis(),
        addTable: vi.fn().mockReturnThis(),
        addRaw: vi.fn().mockReturnThis(),
        write: vi.fn().mockResolvedValue(undefined),
      };

      vi.spyOn(core, "summary", "get").mockReturnValue(
        mockSummary as unknown as typeof core.summary,
      );
    });

    afterEach(() => {
      process.env = originalEnv;
      vi.restoreAllMocks();
    });

    it("should display link to control plane when controlPlaneApiBaseUrl is provided", async () => {
      const connections: Connection[] = [];
      const controlPlaneAppBaseUrl = "https://app.bullfrogsec.com/";
      const workflowRunId = "12345";
      const runAttempt = 1;

      await displaySummary(
        connections,
        controlPlaneAppBaseUrl,
        workflowRunId,
        runAttempt,
      );

      const summary = core.summary;
      expect(summary.addHeading).toHaveBeenCalledWith(
        "Bullfrog Control Plane",
        3,
      );
      expect(summary.addLink).toHaveBeenCalledWith(
        "View detailed results",
        "https://app.bullfrogsec.com/workflow-run/12345",
      );
      expect(summary.write).toHaveBeenCalled();
    });

    it("should handle controlPlaneApiBaseUrl without trailing slash", async () => {
      const connections: Connection[] = [];
      const controlPlaneApiBaseUrl = "https://app.bullfrogsec.com/";
      const workflowRunId = "12345";
      const runAttempt = 1;

      await displaySummary(
        connections,
        controlPlaneApiBaseUrl,
        workflowRunId,
        runAttempt,
      );

      const summary = core.summary;
      expect(summary.addLink).toHaveBeenCalledWith(
        "View detailed results",
        "https://app.bullfrogsec.com/workflow-run/12345",
      );
    });

    it("should include attempt query parameter when run attempt is 2 or more", async () => {
      const connections: Connection[] = [];
      const controlPlaneAppBaseUrl = "https://app.bullfrogsec.com/";
      const workflowRunId = "12345";
      const runAttempt = 2;

      await displaySummary(
        connections,
        controlPlaneAppBaseUrl,
        workflowRunId,
        runAttempt,
      );

      const summary = core.summary;
      expect(summary.addLink).toHaveBeenCalledWith(
        "View detailed results",
        "https://app.bullfrogsec.com/workflow-run/12345?attempt=2",
      );
    });

    it("should display regular heading when controlPlaneApiBaseUrl is not provided", async () => {
      const connections: Connection[] = [];

      await displaySummary(connections, undefined, undefined, undefined);

      const summary = core.summary;
      expect(summary.addHeading).toHaveBeenCalledWith("Bullfrog Results", 3);
      expect(summary.addLink).not.toHaveBeenCalled();
      expect(summary.write).toHaveBeenCalled();
    });

    it("should display connections table when connections exist", async () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
      ];

      await displaySummary(connections, undefined, undefined, undefined);

      const summary = core.summary;
      expect(summary.addTable).toHaveBeenCalled();

      // Verify the table data structure
      const tableCall = vi.mocked(summary.addTable).mock.calls[0][0];
      expect(tableCall).toBeDefined();

      // Check header row
      expect(tableCall[0]).toEqual([
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
      ]);

      // Check data row
      expect(tableCall[1]).toEqual([
        "2024-01-01T00:00:00.000Z",
        "example.com",
        "93.184.216.34",
        "443",
        "TCP",
        "IP allowed",
        "✅ Authorized",
        "curl",
        "-",
        "-",
        "-",
      ]);

      expect(summary.write).toHaveBeenCalled();
    });

    it("should handle missing GITHUB_RUN_ID gracefully", async () => {
      const connections: Connection[] = [];
      const controlPlaneApiBaseUrl = "https://api.bullfrogsec.com/";

      delete process.env.GITHUB_RUN_ID;

      await displaySummary(connections, controlPlaneApiBaseUrl, undefined, 1);

      const summary = core.summary;
      expect(summary.addHeading).toHaveBeenCalledWith("Bullfrog Results", 3);
      expect(summary.addLink).not.toHaveBeenCalled();
      expect(summary.write).toHaveBeenCalled();
    });

    it("should display no connections message when connections array is empty", async () => {
      const connections: Connection[] = [];

      await displaySummary(connections, undefined, undefined, undefined);

      const summary = core.summary;
      expect(summary.addRaw).toHaveBeenCalledWith(
        "\n\nNo outbound connections detected.\n",
      );
      expect(summary.write).toHaveBeenCalled();
    });
  });

  describe("getConnections", () => {
    let originalEnv: NodeJS.ProcessEnv;

    beforeEach(async () => {
      originalEnv = { ...process.env };
      vi.clearAllMocks();

      // Mock timers to skip the 5-second delay
      vi.useFakeTimers();

      // Mock parseInputs
      const { parseInputs } = await import("../inputs");
      vi.mocked(parseInputs).mockReturnValue({
        allowedDomains: [],
        allowedIps: [],
        dnsPolicy: "allowed-domains-only",
        egressPolicy: "audit",
        enableSudo: true,
        collectProcessInfo: true,
        localAgent: false,
        logDirectory: "/var/log/test",
        agentDownloadBaseURL: "https://example.com",
        controlPlaneApiBaseUrl: "https://api.example.com",
        controlPlaneWebappBaseUrl: "https://app.example.com",
        apiToken: undefined,
        githubToken: undefined,
        agentBinaryOwner: "bullfrogsec",
      });

      // Mock core.debug
      vi.mocked(core.debug).mockImplementation(() => {});
      vi.mocked(core.warning).mockImplementation(() => {});
    });

    afterEach(() => {
      process.env = originalEnv;
      vi.useRealTimers();
      vi.restoreAllMocks();
    });

    // Helper to call getConnections and advance timers
    async function callGetConnections() {
      const promise = getConnections();
      await vi.advanceTimersByTimeAsync(5000);
      return promise;
    }

    it("should parse valid connection log entries", async () => {
      const logContent = JSON.stringify({
        timestamp: "1704067200000",
        decision: "allowed",
        protocol: "TCP",
        dstIP: "93.184.216.34",
        dstPort: "443",
        domain: "example.com",
        reason: "ip-allowed",
        processName: "curl",
        commandLine: "curl https://example.com",
        executablePath: "/usr/bin/curl",
      });

      vi.mocked(fs.readFile).mockResolvedValue(logContent);

      const result = await callGetConnections();

      expect(result.raw).toHaveLength(1);
      expect(result.raw[0]).toMatchObject({
        domain: "example.com",
        ip: "93.184.216.34",
        port: 443,
        authorized: true,
        blocked: false,
        protocol: "TCP",
        reason: "ip-allowed",
        process: "curl",
      });
    });

    it("should handle multiple log entries", async () => {
      const logContent = [
        JSON.stringify({
          timestamp: "1704067200000",
          decision: "allowed",
          protocol: "TCP",
          dstIP: "93.184.216.34",
          dstPort: "443",
          domain: "example.com",
          reason: "ip-allowed",
          processName: "curl",
        }),
        JSON.stringify({
          timestamp: "1704067201000",
          decision: "blocked",
          protocol: "TCP",
          dstIP: "1.2.3.4",
          dstPort: "443",
          domain: "malicious.com",
          reason: "domain-not-allowed",
          processName: "wget",
        }),
      ].join("\n");

      vi.mocked(fs.readFile).mockResolvedValue(logContent);

      const result = await callGetConnections();

      expect(result.raw).toHaveLength(2);
      expect(result.raw[0].authorized).toBe(true);
      expect(result.raw[1].authorized).toBe(false);
    });

    it("should handle unknown values by converting to undefined", async () => {
      const logContent = JSON.stringify({
        timestamp: "1704067200000",
        decision: "allowed",
        protocol: "TCP",
        dstIP: "unknown",
        dstPort: "unknown",
        domain: "unknown",
        reason: "ip-allowed",
        processName: "unknown",
        commandLine: "unknown",
        executablePath: "unknown",
      });

      vi.mocked(fs.readFile).mockResolvedValue(logContent);

      const result = await callGetConnections();

      expect(result.raw).toHaveLength(1);
      expect(result.raw[0].domain).toBeUndefined();
      expect(result.raw[0].ip).toBeUndefined();
      expect(result.raw[0].port).toBeUndefined();
      expect(result.raw[0].process).toBeUndefined();
      expect(result.raw[0].exePath).toBeUndefined();
      expect(result.raw[0].commandLine).toBeUndefined();
    });

    it("should skip empty lines", async () => {
      const logContent = [
        JSON.stringify({
          timestamp: "1704067200000",
          decision: "allowed",
          protocol: "TCP",
          dstIP: "93.184.216.34",
          dstPort: "443",
          domain: "example.com",
          reason: "ip-allowed",
          processName: "curl",
        }),
        "",
        "   ",
        JSON.stringify({
          timestamp: "1704067201000",
          decision: "allowed",
          protocol: "TCP",
          dstIP: "1.2.3.4",
          dstPort: "443",
          domain: "test.com",
          reason: "ip-allowed",
          processName: "wget",
        }),
      ].join("\n");

      vi.mocked(fs.readFile).mockResolvedValue(logContent);

      const result = await callGetConnections();

      expect(result.raw).toHaveLength(2);
    });

    it("should skip lines with invalid JSON", async () => {
      const logContent = [
        JSON.stringify({
          timestamp: "1704067200000",
          decision: "allowed",
          protocol: "TCP",
          dstIP: "93.184.216.34",
          dstPort: "443",
          domain: "example.com",
          reason: "ip-allowed",
          processName: "curl",
        }),
        "invalid json line",
        JSON.stringify({
          timestamp: "1704067201000",
          decision: "allowed",
          protocol: "TCP",
          dstIP: "1.2.3.4",
          dstPort: "443",
          domain: "test.com",
          reason: "ip-allowed",
          processName: "wget",
        }),
      ].join("\n");

      vi.mocked(fs.readFile).mockResolvedValue(logContent);

      const result = await callGetConnections();

      expect(result.raw).toHaveLength(2);
      expect(core.warning).toHaveBeenCalledWith(
        "Failed to parse log line: invalid json line",
      );
    });

    it("should skip lines with invalid timestamps", async () => {
      const logContent = [
        JSON.stringify({
          timestamp: "invalid",
          decision: "allowed",
          protocol: "TCP",
          dstIP: "93.184.216.34",
          dstPort: "443",
          domain: "example.com",
          reason: "ip-allowed",
          processName: "curl",
        }),
        JSON.stringify({
          timestamp: "1704067201000",
          decision: "allowed",
          protocol: "TCP",
          dstIP: "1.2.3.4",
          dstPort: "443",
          domain: "test.com",
          reason: "ip-allowed",
          processName: "wget",
        }),
      ].join("\n");

      vi.mocked(fs.readFile).mockResolvedValue(logContent);

      const result = await callGetConnections();

      expect(result.raw).toHaveLength(1);
      expect(result.raw[0].domain).toBe("test.com");
    });

    it("should handle blocked connections when egress-policy is block", async () => {
      const { parseInputs } = await import("../inputs");
      vi.mocked(parseInputs).mockReturnValue({
        allowedDomains: [],
        allowedIps: [],
        dnsPolicy: "allowed-domains-only",
        egressPolicy: "block",
        enableSudo: true,
        collectProcessInfo: true,
        localAgent: false,
        logDirectory: "/var/log/test",
        agentDownloadBaseURL: "https://example.com",
        controlPlaneApiBaseUrl: "https://api.example.com",
        controlPlaneWebappBaseUrl: "https://app.example.com",
        apiToken: undefined,
        githubToken: undefined,
        agentBinaryOwner: "bullfrogsec",
      });

      const logContent = JSON.stringify({
        timestamp: "1704067200000",
        decision: "blocked",
        protocol: "TCP",
        dstIP: "1.2.3.4",
        dstPort: "443",
        domain: "malicious.com",
        reason: "domain-not-allowed",
        processName: "curl",
      });

      vi.mocked(fs.readFile).mockResolvedValue(logContent);

      const result = await callGetConnections();

      expect(result.raw).toHaveLength(1);
      expect(result.raw[0].blocked).toBe(true);
      expect(result.raw[0].authorized).toBe(false);
    });

    it("should return filtered connections using filterConnectionsNoise", async () => {
      const logContent = [
        JSON.stringify({
          timestamp: "1704067200000",
          decision: "allowed",
          protocol: "TCP",
          dstIP: "93.184.216.34",
          dstPort: "443",
          domain: "example.com",
          reason: "ip-allowed",
          processName: "curl",
        }),
        JSON.stringify({
          timestamp: "1704067201000",
          decision: "allowed",
          protocol: "TCP",
          dstIP: "93.184.216.34",
          dstPort: "443",
          domain: "example.com",
          reason: "ip-allowed",
          processName: "curl",
        }),
      ].join("\n");

      vi.mocked(fs.readFile).mockResolvedValue(logContent);

      const result = await callGetConnections();

      expect(result.raw).toHaveLength(2);
      expect(result.filtered).toHaveLength(1); // Deduplicated
    });

    it("should return empty arrays on file read error", async () => {
      vi.mocked(fs.readFile).mockRejectedValue(new Error("File not found"));
      console.error = vi.fn(); // Mock console.error to avoid noise

      const result = await callGetConnections();

      expect(result.raw).toEqual([]);
      expect(result.filtered).toEqual([]);
    });

    it("should handle empty log file", async () => {
      vi.mocked(fs.readFile).mockResolvedValue("");

      const result = await callGetConnections();

      expect(result.raw).toEqual([]);
      expect(result.filtered).toEqual([]);
    });
  });

  describe("submitResultsToControlPlane", () => {
    let originalEnv: NodeJS.ProcessEnv;
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
      originalEnv = { ...process.env };
      process.env.GITHUB_REPOSITORY = "test-org/test-repo";
      process.env.GITHUB_RUN_ID = "12345";
      process.env.GITHUB_RUN_ATTEMPT = "1";
      process.env.GITHUB_JOB = "test-job";

      vi.clearAllMocks();

      // Mock fetch
      fetchMock = vi.fn();
      global.fetch = fetchMock as typeof fetch;

      // Mock core methods
      vi.mocked(core.debug).mockImplementation(() => {});
      vi.mocked(core.info).mockImplementation(() => {});
      vi.mocked(core.warning).mockImplementation(() => {});
    });

    afterEach(() => {
      process.env = originalEnv;
      vi.restoreAllMocks();
    });

    it("should successfully submit results to control plane", async () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
      ];

      fetchMock.mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
      });

      await submitResultsToControlPlane(
        connections,
        "test-token",
        "https://api.bullfrogsec.com/",
      );

      expect(fetchMock).toHaveBeenCalledWith(
        "https://api.bullfrogsec.com/v1/events",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: "Bearer test-token",
          },
          body: expect.stringContaining('"workflowRunId":"12345"'),
        },
      );
    });

    it("should handle control plane URL without trailing slash", async () => {
      const connections: Connection[] = [];

      fetchMock.mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
      });

      await submitResultsToControlPlane(
        connections,
        "test-token",
        "https://api.bullfrogsec.com/",
      );

      expect(fetchMock).toHaveBeenCalledWith(
        "https://api.bullfrogsec.com/v1/events",
        expect.any(Object),
      );
    });

    it("should include all GitHub context in payload", async () => {
      const connections: Connection[] = [];

      fetchMock.mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
      });

      await submitResultsToControlPlane(
        connections,
        "test-token",
        "https://api.bullfrogsec.com/",
      );

      const callArgs = fetchMock.mock.calls[0];
      const payload = JSON.parse(callArgs[1].body);

      expect(payload).toEqual({
        workflowRunId: "12345",
        runAttempt: 1,
        jobName: "test-job",
        organization: "test-org",
        repo: "test-org/test-repo",
        connections: [],
      });
    });

    it("should handle non-OK response", async () => {
      const connections: Connection[] = [];

      fetchMock.mockResolvedValue({
        ok: false,
        status: 400,
        statusText: "Bad Request",
        text: async () => "Invalid payload",
      });

      await submitResultsToControlPlane(
        connections,
        "test-token",
        "https://api.bullfrogsec.com/",
      );

      expect(core.warning).toHaveBeenCalledWith(
        expect.stringContaining("Failed to submit results to control plane"),
      );
    });

    it("should handle fetch error", async () => {
      const connections: Connection[] = [];

      fetchMock.mockRejectedValue(new Error("Network error"));

      await submitResultsToControlPlane(
        connections,
        "test-token",
        "https://api.bullfrogsec.com/",
      );

      expect(core.warning).toHaveBeenCalledWith(
        expect.stringContaining("Failed to submit results to control plane"),
      );
    });

    it("should handle missing GitHub context gracefully", async () => {
      const connections: Connection[] = [];

      delete process.env.GITHUB_REPOSITORY;

      await submitResultsToControlPlane(
        connections,
        "test-token",
        "https://api.bullfrogsec.com/",
      );

      expect(core.warning).toHaveBeenCalledWith(
        expect.stringContaining("Missing GitHub context"),
      );
    });

    it("should include all connection data in payload", async () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
          exePath: "/usr/bin/curl",
          commandLine: "curl https://example.com",
          docker: {
            containerImage: "nginx:latest",
            containerName: "web",
          },
        },
      ];

      fetchMock.mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
      });

      await submitResultsToControlPlane(
        connections,
        "test-token",
        "https://api.bullfrogsec.com/",
      );

      const callArgs = fetchMock.mock.calls[0];
      const payload = JSON.parse(callArgs[1].body);

      expect(payload.connections).toHaveLength(1);
      expect(payload.connections[0]).toMatchObject({
        domain: "example.com",
        ip: "93.184.216.34",
        port: 443,
        blocked: false,
        authorized: true,
        protocol: "TCP",
        reason: "ip-allowed",
        process: "curl",
        exePath: "/usr/bin/curl",
        commandLine: "curl https://example.com",
        docker: {
          containerImage: "nginx:latest",
          containerName: "web",
        },
      });
    });
  });
});
