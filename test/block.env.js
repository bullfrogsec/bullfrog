process.env["_LOCAL_AGENT"] = "true";
process.env["INPUT_ALLOWED-DOMAINS"] = `
www.google.com
*.docker.io
production.cloudflare.docker.com
docker-images-prod.*.r2.cloudflarestorage.com
`;
process.env["INPUT_EGRESS-POLICY"] = "block";
process.env["INPUT_DNS-POLICY"] = "allowed-domains-only";
process.env["INPUT_ENABLE-SUDO"] = "true";
process.env["INPUT__LOG-DIRECTORY"] = "/tmp/bullfrog/logs";
process.env["INPUT_COLLECT-PROCESS-INFO"] = "true";
