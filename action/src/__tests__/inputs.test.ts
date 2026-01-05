import { describe, it, expect, vi, beforeEach } from "vitest";
import { parseInputs } from "../inputs";
import * as core from "@actions/core";
import { AUDIT, BLOCK, ALLOWED_DOMAINS_ONLY, ANY } from "../constants";

vi.mock("@actions/core");

describe("inputs", () => {
  const defaultInputs: Record<string, string> = {
    "allowed-ips": "",
    "allowed-domains": "",
    "egress-policy": AUDIT,
    "dns-policy": ALLOWED_DOMAINS_ONLY,
    "_log-directory": "/var/log/test",
    "_agent-download-base-url": "https://example.com/releases/download",
    "_control-plane-api-base-url": "https://api.example.com",
    "_control-plane-webapp-base-url": "https://app.example.com",
    "api-token": "",
  };
  beforeEach(() => {
    vi.clearAllMocks();

    // Set default valid inputs
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      return defaultInputs[name] || "";
    });

    vi.mocked(core.getBooleanInput).mockImplementation((name: string) => {
      const defaults: Record<string, boolean> = {
        "enable-sudo": true,
        "collect-process-info": true,
      };
      return defaults[name] || false;
    });

    delete process.env["_LOCAL_AGENT"];
  });

  describe("parseInputs", () => {
    it("should parse valid inputs with default values", () => {
      const inputs = parseInputs();

      expect(inputs).toMatchObject({
        allowedDomains: [],
        allowedIps: [],
        dnsPolicy: ALLOWED_DOMAINS_ONLY,
        egressPolicy: AUDIT,
        enableSudo: true,
        collectProcessInfo: true,
        localAgent: false,
        logDirectory: "/var/log/test",
        agentDownloadBaseURL: "https://example.com/releases/download/",
        controlPlaneApiBaseUrl: "https://api.example.com/",
        controlPlaneWebappBaseUrl: "https://app.example.com/",
        apiToken: undefined,
      });
    });

    it("should parse allowed IPs from newline-separated string", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "allowed-ips") return "10.0.0.1\n192.168.1.0/24";
        return defaultInputs[name] || "";
      });

      const inputs = parseInputs();

      expect(inputs.allowedIps).toEqual(["10.0.0.1", "192.168.1.0/24"]);
    });

    it("should parse allowed domains from newline-separated string", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "allowed-domains") return "example.com\n*.google.com";
        return defaultInputs[name] || "";
      });

      const inputs = parseInputs();

      expect(inputs.allowedDomains).toEqual(["example.com", "*.google.com"]);
    });

    it("should accept BLOCK egress policy", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "egress-policy") return BLOCK;
        return defaultInputs[name] || "";
      });

      const inputs = parseInputs();

      expect(inputs.egressPolicy).toBe(BLOCK);
    });

    it("should throw error for invalid egress policy", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "egress-policy") return "invalid";
        return defaultInputs[name] || "";
      });

      expect(() => parseInputs()).toThrow(
        `egress-policy must be '${AUDIT}' or '${BLOCK}'`,
      );
    });

    it("should accept ANY dns policy", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "dns-policy") return ANY;
        return defaultInputs[name] || "";
      });

      const inputs = parseInputs();

      expect(inputs.dnsPolicy).toBe(ANY);
    });

    it("should throw error for invalid dns policy", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "dns-policy") return "invalid";
        return defaultInputs[name] || "";
      });

      expect(() => parseInputs()).toThrow(
        `dns-policy must be '${ALLOWED_DOMAINS_ONLY}' or '${ANY}'`,
      );
    });

    it("should parse boolean inputs correctly", () => {
      vi.mocked(core.getBooleanInput).mockImplementation((name: string) => {
        if (name === "enable-sudo") return true;
        if (name === "collect-process-info") return true;
        return false;
      });

      const inputs = parseInputs();

      expect(inputs.enableSudo).toBe(true);
      expect(inputs.collectProcessInfo).toBe(true);
    });

    it("should detect local agent from environment variable", () => {
      process.env["_LOCAL_AGENT"] = "true";

      const inputs = parseInputs();

      expect(inputs.localAgent).toBe(true);
    });

    it("should not detect local agent when env var is false", () => {
      process.env["_LOCAL_AGENT"] = "false";

      const inputs = parseInputs();

      expect(inputs.localAgent).toBe(false);
    });

    it("should throw error for missing _agent-download-base-url when not using local agent", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "_agent-download-base-url") return "";
        return defaultInputs[name] || "";
      });

      expect(() => parseInputs()).toThrow(
        `_agent-download-base-url cannot be empty`,
      );
    });

    it("should parse api-token when provided", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "api-token") return "test-token-123";
        return defaultInputs[name] || "";
      });

      const inputs = parseInputs();

      expect(inputs.apiToken).toBe("test-token-123");
    });
  });

  describe("IP validation", () => {
    it("should accept valid IPv4 addresses", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "allowed-ips") return "192.168.1.1";
        return defaultInputs[name] || "";
      });

      expect(() => parseInputs()).not.toThrow();
    });

    it("should accept valid CIDR ranges", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "allowed-ips") return "10.0.0.0/24\n192.168.0.0/16";
        return defaultInputs[name] || "";
      });

      expect(() => parseInputs()).not.toThrow();
    });

    it("should reject IPs with invalid characters", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "allowed-ips") return "192.168.1.1abc";
        return defaultInputs[name] || "";
      });

      expect(() => parseInputs()).toThrow("Invalid IP: 192.168.1.1abc");
    });

    it("should reject IPs with letters", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "allowed-ips") return "invalid-ip";
        return defaultInputs[name] || "";
      });

      expect(() => parseInputs()).toThrow("Invalid IP: invalid-ip");
    });

    it("should reject IPs with special characters except dots and slashes", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "allowed-ips") return "192.168.1.1:8080";
        return defaultInputs[name] || "";
      });

      expect(() => parseInputs()).toThrow("Invalid IP: 192.168.1.1:8080");
    });
  });

  describe("Domain validation", () => {
    it("should accept valid domains", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "allowed-domains") return "example.com";
        return defaultInputs[name] || "";
      });

      expect(() => parseInputs()).not.toThrow();
    });

    it("should accept domains with hyphens", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "allowed-domains") return "my-domain.com";
        return defaultInputs[name] || "";
      });

      expect(() => parseInputs()).not.toThrow();
    });

    it("should accept domains with wildcards", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "allowed-domains") return "*.example.com";
        return defaultInputs[name] || "";
      });

      expect(() => parseInputs()).not.toThrow();
    });

    it("should accept domains with multiple subdomains", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        return defaultInputs[name] || "";
      });

      expect(() => parseInputs()).not.toThrow();
    });

    it("should accept domains with numbers", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "allowed-domains") return "example123.com";
        return defaultInputs[name] || "";
      });

      expect(() => parseInputs()).not.toThrow();
    });

    it("should reject domains with invalid characters", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "allowed-domains") return "example.com/path";
        return defaultInputs[name] || "";
      });

      expect(() => parseInputs()).toThrow("Invalid domain: example.com/path");
    });

    it("should reject domains with underscores", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "allowed-domains") return "invalid_domain.com";
        return defaultInputs[name] || "";
      });

      expect(() => parseInputs()).toThrow("Invalid domain: invalid_domain.com");
    });

    it("should reject domains with spaces", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "allowed-domains") return "invalid domain.com";
        return defaultInputs[name] || "";
      });

      expect(() => parseInputs()).toThrow("Invalid domain: invalid domain.com");
    });

    it("should reject domains with special characters", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "allowed-domains") return "example@domain.com";
        return defaultInputs[name] || "";
      });

      expect(() => parseInputs()).toThrow("Invalid domain: example@domain.com");
    });
  });

  describe("Edge cases", () => {
    it("should handle empty allowed IPs", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "allowed-ips") return "";
        return defaultInputs[name] || "";
      });

      const inputs = parseInputs();

      expect(inputs.allowedIps).toEqual([]);
    });

    it("should handle empty allowed domains", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "allowed-domains") return "";
        return defaultInputs[name] || "";
      });

      const inputs = parseInputs();

      expect(inputs.allowedDomains).toEqual([]);
    });

    it("should handle multiple IPs and domains", () => {
      vi.mocked(core.getInput).mockImplementation((name: string) => {
        if (name === "allowed-ips")
          return "10.0.0.1\n192.168.1.0/24\n172.16.0.0/12";
        if (name === "allowed-domains")
          return "example.com\n*.google.com\napi.test.com";
        return defaultInputs[name] || "";
      });

      const inputs = parseInputs();

      expect(inputs.allowedIps).toHaveLength(3);
      expect(inputs.allowedDomains).toHaveLength(3);
    });
  });
});
