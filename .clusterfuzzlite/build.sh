#!/bin/bash -eu

# Build fuzz targets for the bullfrog agent

cd $SRC/bullfrog/agent

# Compile each fuzz test into a libFuzzer-compatible binary
# The compile_go_fuzzer script is provided by the OSS-Fuzz base image

compile_go_fuzzer github.com/bullfrogsec/bullfrog/agent/pkg/agent FuzzExtractDNSFromTCPPayload fuzz_dns_tcp_payload
compile_go_fuzzer github.com/bullfrogsec/bullfrog/agent/pkg/agent FuzzExtractDomainFromSRV fuzz_domain_srv
compile_go_fuzzer github.com/bullfrogsec/bullfrog/agent/pkg/agent FuzzIsDomainAllowed fuzz_domain_allowed
compile_go_fuzzer github.com/bullfrogsec/bullfrog/agent/pkg/agent FuzzIsIpAllowed fuzz_ip_allowed
compile_go_fuzzer github.com/bullfrogsec/bullfrog/agent/pkg/agent FuzzLoadAllowedIp fuzz_load_allowed_ip
compile_go_fuzzer github.com/bullfrogsec/bullfrog/agent/pkg/agent FuzzProcessDNSQuery fuzz_process_dns_query
compile_go_fuzzer github.com/bullfrogsec/bullfrog/agent/pkg/agent FuzzConnectionLog fuzz_connection_log
compile_go_fuzzer github.com/bullfrogsec/bullfrog/agent/pkg/agent FuzzProcessPacket fuzz_process_packet
