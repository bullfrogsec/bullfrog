process.env["INPUT_EGRESS-POLICY"] = "block";
process.env["INPUT_DNS-POLICY"] = "allowed-domains-only";
process.env["INPUT__LOG-DIRECTORY"] = "/tmp/gha-agent/logs";

process.env["INPUT_ALLOWED-IPS"] = `
10.0.0.0/24
`;
process.env["INPUT_ALLOWED-DOMAINS"] = `
*.google.com
bing.com
*.github.com
`;

// uncomment to test with local agent or download release
process.env["_LOCAL_AGENT"] = "true";
// process.env["INPUT__AGENT-DOWNLOAD-BASE-URL"] =
// ("https://github.com/bullfrogsec/bullfrog/releases/download/");
