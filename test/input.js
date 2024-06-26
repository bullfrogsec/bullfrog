process.env["INPUT_EGRESS-POLICY"] = "block";
process.env["INPUT_DNS-POLICY"] = "allowed-domains-only";
process.env["INPUT_LOG-DIRECTORY"] = "/tmp/gha-agent/logs";

process.env["INPUT_ALLOWED-DOMAINS"] = `
*.google.com
bing.com
`;
