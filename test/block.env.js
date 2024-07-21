process.env["_LOCAL_AGENT"] = "true";
process.env["INPUT_ALLOWED-DOMAINS"] = `
www.google.com
`;
process.env["INPUT_EGRESS-POLICY"] = "block";
process.env["INPUT_DNS-POLICY"] = "allowed-domains-only";
process.env["INPUT_ENABLE-SUDO"] = "true";
process.env["INPUT__LOG-DIRECTORY"] = "/tmp/bullfrog/logs";
