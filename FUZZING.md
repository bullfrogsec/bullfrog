# Fuzzing

This document describes the fuzzing infrastructure for the Bullfrog Go agent.

## Overview

Bullfrog uses two complementary approaches to fuzzing:

1. **Native Go Fuzzing** - Simple, built-in Go fuzzing using Go 1.18+ native fuzz tests
2. **ClusterFuzzLite** - Advanced continuous fuzzing integrated with GitHub Actions

## Native Go Fuzzing

### Running Locally

To run fuzz tests locally:

```bash
cd agent

# Run all fuzz tests for 30 seconds each
go test ./pkg/agent -fuzz=. -fuzztime=30s

# Run a specific fuzz test
go test ./pkg/agent -fuzz=FuzzExtractDNSFromTCPPayload -fuzztime=1m

# Run with specific number of iterations
go test ./pkg/agent -fuzz=FuzzIsDomainAllowed -fuzztime=100000x
```

### Available Fuzz Tests

The following fuzz tests are available in `agent/pkg/agent/agent_fuzz_test.go`:

- **FuzzExtractDNSFromTCPPayload** - Tests DNS-over-TCP payload parsing
- **FuzzExtractDomainFromSRV** - Tests SRV domain extraction
- **FuzzIsDomainAllowed** - Tests domain matching with wildcards
- **FuzzIsIpAllowed** - Tests IP and CIDR matching
- **FuzzLoadAllowedIp** - Tests IP/CIDR parsing
- **FuzzProcessDNSQuery** - Tests DNS query processing
- **FuzzConnectionLog** - Tests JSON marshaling of connection logs
- **FuzzProcessPacket** - Tests the main packet processing pipeline

### Crash Artifacts

When a fuzz test finds a crash, the failing input is saved to:
```
agent/pkg/agent/testdata/fuzz/<FuzzTestName>/<hash>
```

You can reproduce the crash by running:
```bash
go test ./pkg/agent -run=<FuzzTestName>
```

## GitHub Actions Integration

### Native Fuzzing Workflow

The `.github/workflows/fuzz.yml` workflow runs native Go fuzzing on:
- Pull requests that modify Go code in the agent
- Daily at 2 AM UTC
- Manual dispatch via GitHub UI

**Configuration:**
- Default fuzz time: 60 seconds per test
- Can be customized via workflow dispatch input

**Results:**
- Crashes are uploaded as GitHub Actions artifacts
- Workflow fails if any fuzz test finds a crash

### ClusterFuzzLite Workflows

ClusterFuzzLite provides more advanced continuous fuzzing:

#### PR Fuzzing (`.github/workflows/cflite_pr.yml`)
- Runs on pull requests
- Fuzzes code changes for 10 minutes per test
- Reports crashes in PR

#### Batch Fuzzing (`.github/workflows/cflite_batch.yml`)
- Runs every 6 hours on main branch
- Fuzzes for 1 hour per test
- Builds corpus over time

#### Continuous Builds (`.github/workflows/cflite_build.yml`)
- Builds fuzzers on every push to main
- Used to detect newly introduced crashes

#### Cron Tasks (`.github/workflows/cflite_cron.yml`)
- Runs daily
- Prunes corpus to remove redundant inputs
- Generates coverage reports

## ClusterFuzzLite Configuration

The ClusterFuzzLite configuration is in `.clusterfuzzlite/`:

- **project.yaml** - Language and sanitizer configuration
- **Dockerfile** - Base image for building fuzzers
- **build.sh** - Script to compile fuzz tests into libFuzzer-compatible binaries

## Supported Sanitizers

- **Address Sanitizer (ASan)** - Detects memory safety issues
  - Buffer overflows
  - Use-after-free
  - Double-free
  - Memory leaks

Note: Go only supports the address sanitizer. Other sanitizers (undefined behavior, memory sanitizer) are not available for Go.

## Best Practices

1. **Add fuzz tests for new parsing code** - Any code that processes external input should have a fuzz test
2. **Review and fix crashes promptly** - Fuzzing will find real bugs, fix them before merging
3. **Add interesting inputs to seed corpus** - Use `f.Add()` in fuzz tests to add known edge cases
4. **Run locally before pushing** - Quick local fuzzing can catch obvious issues

## Scorecard Compliance

This fuzzing setup addresses the OpenSSF Scorecard requirement for fuzzing:
- ✅ Native Go fuzz tests are present and detected by scorecard
- ✅ ClusterFuzzLite provides continuous fuzzing in CI
- ✅ Fuzz tests cover critical parsing and decision-making code

## Resources

- [Go Fuzzing Tutorial](https://go.dev/doc/tutorial/fuzz)
- [ClusterFuzzLite Documentation](https://google.github.io/clusterfuzzlite/)
- [OSS-Fuzz](https://google.github.io/oss-fuzz/)
