package agent

import (
	"time"

	"github.com/google/gopacket/layers"
)

// Constants for packet verdicts and policies
const (
	ACCEPT_REQUEST                  uint8 = 0
	DROP_REQUEST                    uint8 = 1
	EGRESS_POLICY_BLOCK                   = "block"
	EGRESS_POLICY_AUDIT                   = "audit"
	DNS_POLICY_ALLOWED_DOMAINS_ONLY       = "allowed-domains-only"
	DNS_POLICY_ANY                        = "any"
	DNS_PORT                              = layers.TCPPort(53)
)

// Package-private default configurations
var (
	defaultDomains = []string{
		"*.actions.githubusercontent.com",
		"*.githubapp.com",
		"glb-*.github.com",
		"productionresultssa0.blob.core.windows.net",
		"productionresultssa1.blob.core.windows.net",
		"productionresultssa2.blob.core.windows.net",
		"productionresultssa3.blob.core.windows.net",
		"productionresultssa4.blob.core.windows.net",
		"productionresultssa5.blob.core.windows.net",
		"productionresultssa6.blob.core.windows.net",
		"productionresultssa7.blob.core.windows.net",
		"productionresultssa8.blob.core.windows.net",
		"productionresultssa9.blob.core.windows.net",
		"productionresultssa10.blob.core.windows.net",
		"productionresultssa11.blob.core.windows.net",
		"productionresultssa12.blob.core.windows.net",
		"productionresultssa13.blob.core.windows.net",
		"productionresultssa14.blob.core.windows.net",
		"productionresultssa15.blob.core.windows.net",
		"productionresultssa16.blob.core.windows.net",
		"productionresultssa17.blob.core.windows.net",
		"productionresultssa18.blob.core.windows.net",
		"productionresultssa19.blob.core.windows.net",
	}
	defaultIps        = []string{"168.63.129.16", "169.254.169.254", "127.0.0.1"}
	defaultDNSServers = []string{"127.0.0.53"}
)

// DockerInfo contains information about a Docker container
type DockerInfo struct {
	ContainerImage string `json:"containerImage"`
	ContainerName  string `json:"containerName"`
}

// ConnectionLog represents a logged network connection attempt
type ConnectionLog struct {
	Timestamp      int64       `json:"timestamp"`
	Decision       string      `json:"decision"`
	Protocol       string      `json:"protocol"`
	SrcIP          string      `json:"srcIP"`
	SrcPort        string      `json:"srcPort"`
	DstIP          string      `json:"dstIP"`
	DstPort        string      `json:"dstPort"`
	Domain         string      `json:"domain"`
	Reason         string      `json:"reason"`
	PID            int         `json:"pid"`
	ProcessName    string      `json:"processName"`
	CommandLine    string      `json:"commandLine"`
	ExecutablePath string      `json:"executablePath"`
	ProcessingTime int64       `json:"processingTime"`
	Docker         *DockerInfo `json:"docker,omitempty"`
}

// PacketInfo holds information extracted from a network packet
type PacketInfo struct {
	SrcIP          string
	SrcPort        string
	DstIP          string
	DstPort        string
	PID            int
	ProcessName    string
	CommandLine    string
	ExecutablePath string
	Docker         *DockerInfo
	StartTime      time.Time
}

// AgentConfig configures the Agent behavior
type AgentConfig struct {
	EgressPolicy       string
	DNSPolicy          string
	AllowedDomains     []string
	AllowedIPs         []string
	EnableSudo         bool
	CollectProcessInfo bool
	NetInfoProvider    INetInfoProvider
	FileSystem         IFileSystem
	ProcProvider       IProcProvider
	DockerProvider     IDockerProvider
}

// ProcessInfo holds process identification data
type ProcessInfo struct {
	PID            int
	ProcessName    string      // From /proc/[pid]/comm
	CommandLine    string      // From /proc/[pid]/cmdline (full command with args)
	ExecutablePath string      // From /proc/[pid]/exe (actual binary location)
	Docker         *DockerInfo // Docker container info if process is in a container
	Timestamp      int64
}

// SocketEntry represents a parsed line from /proc/net/{tcp,udp}
type SocketEntry struct {
	LocalAddr  string // Hex format: "0100007F:0277"
	RemoteAddr string
	State      string
	Inode      uint64
}
