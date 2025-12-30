package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"regexp"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	blocking       = false
	defaultDomains = []string{
		"*.actions.githubusercontent.com",
		"*.githubapp.com",
		"glb-*.github.com",
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

const (
	ACCEPT_REQUEST                  uint8 = 0
	DROP_REQUEST                    uint8 = 1
	EGRESS_POLICY_BLOCK                   = "block"
	EGRESS_POLICY_AUDIT                   = "audit"
	DNS_POLICY_ALLOWED_DOMAINS_ONLY       = "allowed-domains-only"
	DNS_POLICY_ANY                        = "any"
	DNS_PORT                              = layers.TCPPort(53)
)

type ConnectionLog struct {
	Decision       string
	Protocol       string
	SrcIP          string
	SrcPort        string
	DstIP          string
	DstPort        string
	Domain         string
	Reason         string
	PID            int
	ProcessName    string
	CommandLine    string
	ExecutablePath string
	ProcessingTime time.Duration
}

type PacketInfo struct {
	SrcIP          string
	SrcPort        string
	DstIP          string
	DstPort        string
	PID            int
	ProcessName    string
	CommandLine    string
	ExecutablePath string
	StartTime      time.Time
}

type AgentConfig struct {
	EgressPolicy    string
	DNSPolicy       string
	AllowedDomains  []string
	AllowedIPs      []string
	EnableSudo      bool
	NetInfoProvider INetInfoProvider
	FileSystem      IFileSystem
	ProcProvider    IProcProvider
	DockerProvider  IDockerProvider
}

type Agent struct {
	blockDNS          bool
	blocking          bool
	allowedDomains    map[string]bool
	allowedIps        map[string]bool
	allowedDNSServers map[string]bool
	allowedCIDR       []*net.IPNet
	ipToDomain        map[string]string // Reverse mapping: IP -> domain name for logging
	netInfoProvider   INetInfoProvider
	filesystem        IFileSystem
	processInfoCache  map[string]*ProcessInfo
	procProvider      IProcProvider
	dockerProvider    IDockerProvider
}

func NewAgent(config AgentConfig) *Agent {
	agent := &Agent{
		blockDNS:          false,
		blocking:          false,
		allowedDomains:    make(map[string]bool),
		allowedIps:        make(map[string]bool),
		allowedDNSServers: make(map[string]bool),
		ipToDomain:        make(map[string]string),
		netInfoProvider:   config.NetInfoProvider,
		filesystem:        config.FileSystem,
		processInfoCache:  make(map[string]*ProcessInfo),
		procProvider:      config.ProcProvider,
		dockerProvider:    config.DockerProvider,
	}

	// If no Docker provider specified, try to create one
	if agent.dockerProvider == nil {
		dockerProvider, err := NewDockerProvider()
		if err != nil {
			log.Printf("Docker unavailable, using NullDockerProvider: %v", err)
			agent.dockerProvider = &NullDockerProvider{}
		} else {
			log.Printf("Docker provider initialized successfully")
			agent.dockerProvider = dockerProvider
		}
	}

	agent.init(config)
	return agent
}

func (a *Agent) init(config AgentConfig) error {

	fmt.Printf("Egress policy: %s\n", config.EgressPolicy)
	fmt.Printf("DNS policy: %s\n", config.DNSPolicy)
	fmt.Printf("Allowed domains: %v\n", config.AllowedDomains)
	fmt.Printf("Allowed IPs: %v\n", config.AllowedIPs)

	if config.EgressPolicy == EGRESS_POLICY_BLOCK {
		a.blocking = true
		fmt.Println("Blocking mode enabled")
	} else {
		fmt.Println("Audit mode enabled")
	}

	if a.blocking {
		if config.DNSPolicy == DNS_POLICY_ALLOWED_DOMAINS_ONLY {
			a.blockDNS = true
			fmt.Println("DNS queries to unallowed domains will be blocked")
		}
	}

	a.loadAllowedIp(config.AllowedIPs)
	a.loadAllowedDomain(config.AllowedDomains)

	if !config.EnableSudo {
		if err := a.disableSudo(); err != nil {
			log.Fatalln("Could not disable sudo")
		}
	}

	err := a.loadAllowedDNSServers()
	if err != nil {
		log.Fatalf("Loading DNS servers allowlist: %v", err)
	}

	// No longer need to add IPs to nftables - Go agent makes all decisions
	// Just flush DNS cache to ensure fresh resolutions
	err = a.netInfoProvider.FlushDNSCache()
	if err != nil {
		log.Printf("Error flushing DNS cache: %v", err)
	}
	return nil
}

func (a *Agent) loadAllowedDomain(domains []string) {

	fmt.Println("loading allowed domains")

	mergedDomains := append(defaultDomains, domains...)

	// loads default first
	for _, domain := range mergedDomains {
		if domain == "" {
			continue
		}
		fmt.Printf("Domain: %s\n", domain)
		a.allowedDomains[domain] = true
	}
}

func (a *Agent) loadAllowedIp(ips []string) {

	fmt.Println("loading allowed ips")

	mergedIps := append(defaultIps, ips...)

	for _, ip := range mergedIps {
		if ip == "" {
			continue
		}
		fmt.Printf("IP: %s\n", ip)
		_, cidr, err := net.ParseCIDR(ip)
		if err == nil {
			fmt.Printf("CIDR: %s\n", cidr)
			a.allowedCIDR = append(a.allowedCIDR, cidr)
			continue
		}

		netIp := net.ParseIP(ip)
		if netIp != nil {
			a.allowedIps[ip] = true
			continue
		}
		fmt.Printf("failed to parse ip: %s. skipping.\n", ip)
	}
}

func (a *Agent) isDomainAllowed(domain string) bool {
	if a.allowedDomains[domain] {
		return true
	}
	for allowedDomain := range a.allowedDomains {
		match, _ := path.Match(allowedDomain, domain)
		if match {
			return true
		}
	}
	return false
}

func (a *Agent) isIpAllowed(ipStr string) bool {
	if a.allowedIps[ipStr] {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		fmt.Printf("Failed to parse IP: %s\n", ipStr)
		return false
	}
	for _, cidr := range a.allowedCIDR {
		if cidr.Contains(ip) {
			a.allowedIps[ipStr] = true
			return true
		}
	}
	return false
}

func (a *Agent) getCachedOrLookupProcess(srcIP, srcPort, protocol string) (int, string, string, string) {
	cacheKey := fmt.Sprintf("%s:%s:%s", srcIP, srcPort, protocol)

	// Check cache first
	if cached, exists := a.processInfoCache[cacheKey]; exists {
		return cached.PID, cached.ProcessName, cached.CommandLine, cached.ExecutablePath
	}

	// Try Docker container lookup first, but only if the IP is from a Docker network
	if isDockerIP(srcIP) {
		if container, err := a.dockerProvider.FindContainerByIP(srcIP); err == nil && container != nil {
			pid, processName, cmdLine, execPath, err := a.dockerProvider.GetProcessInContainer(
				container, srcIP, srcPort, protocol)

			if err == nil {
				// Format: "container-image:container-name:process-name"
				formattedName := fmt.Sprintf("docker:%s;%s;%s", container.Image, container.Name, processName)

				// Cache the result
				a.processInfoCache[cacheKey] = &ProcessInfo{
					PID:            pid,
					ProcessName:    formattedName,
					CommandLine:    cmdLine,
					ExecutablePath: execPath,
					Timestamp:      time.Now().Unix(),
				}

				return pid, formattedName, cmdLine, execPath
			}

			// Log error per user's preference
			log.Printf("Docker process lookup failed for %s in container %s: %v",
				cacheKey, container.Name, err)
		} else if err != nil && err.Error() != "Docker not available" {
			// Log Docker API errors (but not if Docker is simply unavailable)
			log.Printf("Docker container lookup failed for IP %s: %v", srcIP, err)
		}
	}

	// Fallback to host process lookup
	pid, processName, cmdLine, execPath, err := getProcessInfo(a.procProvider, srcIP, srcPort, protocol)
	if err != nil {
		fmt.Printf("Process lookup failed for %s: %v\n", cacheKey, err)
		return 0, "unknown", "unknown", "unknown"
	}

	// Cache the result
	a.processInfoCache[cacheKey] = &ProcessInfo{
		PID:            pid,
		ProcessName:    processName,
		CommandLine:    cmdLine,
		ExecutablePath: execPath,
		Timestamp:      time.Now().Unix(),
	}

	return pid, processName, cmdLine, execPath
}

func (a *Agent) addConnectionLog(pkt PacketInfo, decision, protocol, domain, reason string) {

	// Skip logging connections to allowed non-DNS default IPs (metadata services, etc.)
	if decision == "allowed" && pkt.DstPort != "53" {
		for _, defaultIP := range defaultIps {
			if pkt.DstIP == defaultIP {
				return
			}
		}
	}

	content := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s|%s|%d|%s|%s|%s|%d\n",
		time.Now().UnixMilli(),
		decision,
		protocol,
		pkt.SrcIP,
		pkt.SrcPort,
		pkt.DstIP,
		pkt.DstPort,
		domain,
		reason,
		pkt.PID,
		pkt.ProcessName,
		pkt.CommandLine,
		pkt.ExecutablePath,
		time.Since(pkt.StartTime).Milliseconds())
	a.filesystem.Append("/var/log/gha-agent/connections.log", content)
}

func (a *Agent) loadAllowedDNSServers() error {

	dnsServer, err := a.netInfoProvider.GetDNSServer()
	if err != nil {
		return err
	}
	mergedDNSServers := append(defaultDNSServers, dnsServer)

	for _, dns := range mergedDNSServers {
		a.allowedDNSServers[dns] = true
	}

	return nil
}

func tcpPortToString(port layers.TCPPort) string {
	return strconv.Itoa(int(port))
}

func udpPortToString(port layers.UDPPort) string {
	return strconv.Itoa(int(port))
}

func getDestinationIP(packet gopacket.Packet) (string, error) {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return "", fmt.Errorf("failed to get network layer")
	}

	switch v := netLayer.(type) {
	case *layers.IPv4:
		return v.DstIP.String(), nil
	case *layers.IPv6:
		return v.DstIP.String(), nil
	default:
		return "", fmt.Errorf("unknown network layer type")
	}
}

func (a *Agent) extractPacketInfo(packet gopacket.Packet) PacketInfo {
	info := PacketInfo{
		SrcIP:          "unknown",
		SrcPort:        "unknown",
		DstIP:          "unknown",
		DstPort:        "unknown",
		PID:            0,
		ProcessName:    "unknown",
		CommandLine:    "unknown",
		ExecutablePath: "unknown",
		StartTime:      time.Now(),
	}

	// Extract IPs from network layer
	netLayer := packet.NetworkLayer()
	if netLayer != nil {
		switch v := netLayer.(type) {
		case *layers.IPv4:
			info.SrcIP = v.SrcIP.String()
			info.DstIP = v.DstIP.String()
		case *layers.IPv6:
			info.SrcIP = v.SrcIP.String()
			info.DstIP = v.DstIP.String()
		}
	}

	// Extract ports and determine protocol
	var protocol string
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		info.SrcPort = tcpPortToString(tcp.SrcPort)
		info.DstPort = tcpPortToString(tcp.DstPort)
		protocol = "tcp"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		info.SrcPort = udpPortToString(udp.SrcPort)
		info.DstPort = udpPortToString(udp.DstPort)
		protocol = "udp"
	}

	// Lookup process information
	if protocol != "" && info.SrcIP != "unknown" && info.SrcPort != "unknown" && info.SrcPort != "53" {
		info.PID, info.ProcessName, info.CommandLine, info.ExecutablePath =
			a.getCachedOrLookupProcess(info.SrcIP, info.SrcPort, protocol)
	}

	return info
}

func extractDomainFromSRV(domain string) string {
	// drop the protocol and transport layer subdomains from the SRV DNS query domain
	// only _http._tcp. and _https._tcp are supported for now
	regex := `^_http\._tcp\.|^_https\._tcp\.`
	re := regexp.MustCompile(regex)
	return re.ReplaceAllString(domain, "")
}

func (a *Agent) processDNSLayer(dns *layers.DNS, pkt PacketInfo) uint8 {
	if !dns.QR {
		return a.processDNSQuery(dns, pkt)
	}
	return a.processDNSResponse(dns, pkt)
}

func (a *Agent) processDNSQuery(dns *layers.DNS, pkt PacketInfo) uint8 {
	for _, q := range dns.Questions {
		domain := string(q.Name)
		fmt.Printf("DNS Question: %s %s\n", q.Name, q.Type)

		if q.Type == layers.DNSTypeSRV {
			originalDomain := domain
			domain = extractDomainFromSRV(domain)
			fmt.Printf("%s -> Converting domain from SRV query: %s\n", originalDomain, domain)
		}
		if a.isDomainAllowed(domain) {
			fmt.Printf("%s -> Allowed DNS Query\n", domain)
			a.addConnectionLog(pkt, "allowed", "DNS", domain, "domain-allowed")
			return ACCEPT_REQUEST
		}

		fmt.Printf("%s -> Blocked DNS Query\n", domain)
		a.addConnectionLog(pkt, "blocked", "DNS", domain, "domain-not-allowed")
		return DROP_REQUEST
	}
	return DROP_REQUEST
}

func (a *Agent) processDNSTypeAResponse(domain string, answer *layers.DNSResourceRecord, pkt PacketInfo) {
	fmt.Printf("DNS Answer: %s %s %s\n", answer.Name, answer.Type, answer.IP)
	fmt.Printf("%s:%s", answer.Name, answer.IP)
	ip := answer.IP.String()

	// Store IP-to-domain mapping for connection logging
	a.ipToDomain[ip] = domain

	if a.isDomainAllowed(domain) {
		fmt.Println("-> Allowed request")
		if !a.allowedIps[ip] {
			// Add to in-memory allowed IPs map
			// No need to update nftables - Go agent handles all decisions
			a.allowedIps[ip] = true
			// a.addConnectionLog(ConnectionLog{
			// 	Decision:       "allowed",
			// 	Protocol:       "DNS-response",
			// 	SrcIP:          pkt.SrcIP,
			// 	SrcPort:        pkt.SrcPort,
			// 	DstIP:          ip,
			// 	DstPort:        "53",
			// 	Domain:         domain,
			// 	Reason:         "dns-resolved",
			// 	PID:            pkt.PID,
			// 	ProcessName:    pkt.ProcessName,
			// 	CommandLine:    pkt.CommandLine,
			// 	ExecutablePath: pkt.ExecutablePath,
			// })
		}
	} else if a.isIpAllowed(ip) {
		fmt.Println("-> Allowed request")
		// a.addConnectionLog(ConnectionLog{
		// 	Decision:       "allowed",
		// 	Protocol:       "DNS-response",
		// 	SrcIP:          pkt.SrcIP,
		// 	SrcPort:        pkt.SrcPort,
		// 	DstIP:          ip,
		// 	DstPort:        "53",
		// 	Domain:         domain,
		// 	Reason:         "ip-allowed",
		// 	PID:            pkt.PID,
		// 	ProcessName:    pkt.ProcessName,
		// 	CommandLine:    pkt.CommandLine,
		// 	ExecutablePath: pkt.ExecutablePath,
		// })
	} else {
		// a.addConnectionLog(ConnectionLog{
		// 	Decision:       "blocked",
		// 	Protocol:       "DNS-response",
		// 	SrcIP:          pkt.SrcIP,
		// 	SrcPort:        pkt.SrcPort,
		// 	DstIP:          ip,
		// 	DstPort:        "53",
		// 	Domain:         domain,
		// 	Reason:         "domain-not-allowed",
		// 	PID:            pkt.PID,
		// 	ProcessName:    pkt.ProcessName,
		// 	CommandLine:    pkt.CommandLine,
		// 	ExecutablePath: pkt.ExecutablePath,
		// })
		if blocking {
			fmt.Println("-> Blocked request")
		} else {
			fmt.Println("-> Unallowed request")
		}
	}
}

func (a *Agent) processDNSTypeCNAMEResponse(domain string, answer *layers.DNSResourceRecord) {
	cnameDomain := string(answer.CNAME)
	fmt.Printf("DNS Answer: %s %s %s\n", answer.Name, answer.Type, cnameDomain)
	fmt.Printf("%s:%s", answer.Name, cnameDomain)
	if a.isDomainAllowed(domain) {
		fmt.Println("-> Allowed request")
		if !a.allowedDomains[cnameDomain] {
			fmt.Printf("Adding %s to the allowed domains list\n", cnameDomain)
			a.allowedDomains[cnameDomain] = true
		}
	}
}

func (a *Agent) processDNSTypeSRVResponse(domain string, answer *layers.DNSResourceRecord) {
	srvDomain := string(answer.SRV.Name)
	fmt.Printf("DNS Answer: %s %s %s\n", answer.Name, answer.Type, srvDomain)
	fmt.Printf("%s:%s", answer.Name, srvDomain)
	domain = extractDomainFromSRV(domain)
	if a.isDomainAllowed(domain) {
		fmt.Println("-> Allowed request")
		if !a.allowedDomains[srvDomain] {
			fmt.Printf("Adding %s to the allowed domains list\n", srvDomain)
			a.allowedDomains[srvDomain] = true
		}
	}
}

func (a *Agent) processDNSResponse(dns *layers.DNS, pkt PacketInfo) uint8 {
	domain := string(dns.Questions[0].Name)
	for _, answer := range dns.Answers {
		fmt.Printf("DNS Answer: %s %s %s\n", answer.Name, answer.Type, answer.IP)
		if answer.Type == layers.DNSTypeA {
			a.processDNSTypeAResponse(domain, &answer, pkt)
		} else if answer.Type == layers.DNSTypeCNAME {
			a.processDNSTypeCNAMEResponse(domain, &answer)
		} else if answer.Type == layers.DNSTypeSRV {
			a.processDNSTypeSRVResponse(domain, &answer)
		} else if answer.Type == layers.DNSTypeAAAA {
			fmt.Printf("DNS Answer: %s %s %s\n", answer.Name, answer.Type, answer.IP)
		} else {
			fmt.Printf("DNS Answer (others): %s %s %s\n", answer.Name, answer.Type, answer.IP)
		}
	}
	return ACCEPT_REQUEST
}

func (a *Agent) processDNSPacket(packet gopacket.Packet) uint8 {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	dns, _ := dnsLayer.(*layers.DNS)
	for _, q := range dns.Questions {
		fmt.Printf("DNS Question: %s %s\n", q.Name, q.Type)
	}

	pkt := a.extractPacketInfo(packet)
	domain := string(dns.Questions[0].Name)
	// if we are blocking DNS queries, intercept the DNS queries and decide whether to block or allow them
	if !dns.QR {
		// making sure the DNS query is using a trusted DNS server
		if !a.allowedDNSServers[pkt.DstIP] {
			fmt.Printf("%s -> Blocked DNS Query. Untrusted DNS server %s\n", domain, pkt.DstIP)
			a.addConnectionLog(pkt, "blocked", "DNS", domain, "untrusted-dns-server")
			return DROP_REQUEST
		}
	}

	// if we are not blocking DNS queries, just accept the query request
	if !a.blockDNS && !dns.QR {
		return ACCEPT_REQUEST
	}
	return a.processDNSLayer(dns, pkt)
}

func (a *Agent) processDNSOverTCPPayload(payload []byte, pkt PacketInfo) uint8 {
	// Extract message length from first 2 bytes
	// - First byte shifted left 8 bits + second byte
	// - Creates 16-bit length prefix
	messageLen := int(payload[0])<<8 | int(payload[1])
	if messageLen == 0 || len(payload) < messageLen+2 {
		fmt.Println("Invalid DNS over TCP payload")
		return DROP_REQUEST
	}

	// We attempt to decode the DNS over TCP payload
	// The only way we can accept the request is if the DNS query is contained within a single TCP packet payload
	dns := &layers.DNS{}
	err := dns.DecodeFromBytes(payload[2:messageLen+2], gopacket.NilDecodeFeedback)
	if err != nil {
		fmt.Println("Failed to decode DNS over TCP payload", err)
		return DROP_REQUEST
	}
	return a.processDNSLayer(dns, pkt)
}

func (a *Agent) processTCPPacket(packet gopacket.Packet) uint8 {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcp, _ := tcpLayer.(*layers.TCP)
	dstPort, srcPort, payload := tcp.DstPort, tcp.SrcPort, tcp.Payload

	pkt := a.extractPacketInfo(packet)

	// Validate DNS server IP
	if dstPort == DNS_PORT {
		if !a.allowedDNSServers[pkt.DstIP] {
			fmt.Printf("%s -> Blocked DNS Query. Untrusted DNS server %s\n", "unknown", pkt.DstIP)
			a.addConnectionLog(pkt, "blocked", "TCP-DNS", "unknown", "untrusted-dns-server")
			return DROP_REQUEST
		}
	}

	if dstPort != DNS_PORT && srcPort != DNS_PORT {
		fmt.Println("Warning: Destination and source port are not DNS ports. Dropping request")
		return DROP_REQUEST
	}

	// if we are not blocking DNS queries, just accept the query request
	if !a.blockDNS && dstPort == DNS_PORT {
		return ACCEPT_REQUEST
	}

	if len(payload) == 0 {
		// We only accept DNS over TCP packets with no payload since they are only used for initiating a connection
		return ACCEPT_REQUEST
	}

	// Now we have a payload in the TCP packet, we need to make sure it is a valid DNS over TCP payload and the DNS query is for a known domain. We don't want to exfiltrate data over DNS over TCP
	return a.processDNSOverTCPPayload(payload, pkt)

}

func (a *Agent) processNonDNSPacket(packet gopacket.Packet) uint8 {
	startTime := time.Now()
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		fmt.Println("No network layer found, dropping packet")
		pkt := PacketInfo{
			SrcIP:          "unknown",
			SrcPort:        "unknown",
			DstIP:          "unknown",
			DstPort:        "unknown",
			PID:            0,
			ProcessName:    "unknown",
			CommandLine:    "unknown",
			ExecutablePath: "unknown",
			StartTime:      startTime,
		}
		a.addConnectionLog(pkt, "blocked", "unknown", "unknown", "no-network-layer")
		return DROP_REQUEST
	}

	// Determine protocol from network layer
	var protocol string
	switch v := netLayer.(type) {
	case *layers.IPv4:
		protocol = v.Protocol.String()
	case *layers.IPv6:
		protocol = v.NextHeader.String()
	default:
		fmt.Println("Unknown network layer type, dropping packet")
		pkt := PacketInfo{
			SrcIP:          "unknown",
			SrcPort:        "unknown",
			DstIP:          "unknown",
			DstPort:        "unknown",
			PID:            0,
			ProcessName:    "unknown",
			CommandLine:    "unknown",
			ExecutablePath: "unknown",
			StartTime:      startTime,
		}
		a.addConnectionLog(pkt, "blocked", "unknown", "unknown", "unknown-network-layer")
		return DROP_REQUEST
	}

	// Extract packet info (IPs, ports, process info)
	pkt := a.extractPacketInfo(packet)

	// Look up domain for this IP (if it was resolved via DNS)
	domain, hasDomain := a.ipToDomain[pkt.DstIP]
	if !hasDomain {
		domain = "unknown"
	}

	// Check if destination IP is allowed
	if a.isIpAllowed(pkt.DstIP) {
		fmt.Printf("ALLOW: %s:%s -> %s:%s (%s) [%s]\n", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, protocol, domain)
		a.addConnectionLog(pkt, "allowed", protocol, domain, "ip-allowed")
		return ACCEPT_REQUEST
	}

	// In audit mode, log but allow
	if !a.blocking {
		fmt.Printf("AUDIT: %s:%s -> %s:%s (%s) [%s] - would be blocked\n", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, protocol, domain)
		a.addConnectionLog(pkt, "audit", protocol, domain, "ip-not-allowed")
		return ACCEPT_REQUEST
	}

	// Block mode - drop the packet
	fmt.Printf("BLOCK: %s:%s -> %s:%s (%s) [%s]\n", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, protocol, domain)
	a.addConnectionLog(pkt, "blocked", protocol, domain, "ip-not-allowed")
	return DROP_REQUEST
}

func (a *Agent) ProcessPacket(packet gopacket.Packet) uint8 {
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		return a.processDNSPacket(packet)
	}
	// check dns over tcp
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		// Only treat as DNS if it's actually on port 53
		if tcp.DstPort == DNS_PORT || tcp.SrcPort == DNS_PORT {
			return a.processTCPPacket(packet)
		}
	}
	// Handle all other packets (non-DNS TCP, UDP, ICMP, etc.)
	return a.processNonDNSPacket(packet)
}

func (a *Agent) disableSudo() error {
	return os.Remove("/etc/sudoers.d/runner")
}
