process.env["INPUT_EGRESS-POLICY"] = "block";
process.env["INPUT_DNS_POLICY"] = "allowed-domains-only";
process.env["INPUT_LOG-DIRECTORY"] = "/tmp/gha-agent/logs";

process.env["INPUT_ALLOWED-DOMAINS"] = `
*.google.com
bing.com
`;
