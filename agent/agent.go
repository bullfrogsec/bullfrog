package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"regexp"
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
	Decision string
	Protocol string
	SrcIP    string
	DstIP    string
	DstPort  string
	Domain   string
	Reason   string
}

type AgentConfig struct {
	EgressPolicy    string
	DNSPolicy       string
	AllowedDomains  []string
	AllowedIPs      []string
	EnableSudo      bool
	NetInfoProvider INetInfoProvider
	FileSystem      IFileSystem
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

func (a *Agent) addConnectionLog(log ConnectionLog) {

	// Skip logging connections to default IPs (metadata services, etc.)
	for _, defaultIP := range defaultIps {
		if log.DstIP == defaultIP {
			return
		}
	}

	content := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s\n", time.Now().UnixMilli(), log.Decision, log.Protocol, log.SrcIP, log.DstIP, log.DstPort, log.Domain, log.Reason)
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

func extractDomainFromSRV(domain string) string {
	// drop the protocol and transport layer subdomains from the SRV DNS query domain
	// only _http._tcp. and _https._tcp are supported for now
	regex := `^_http\._tcp\.|^_https\._tcp\.`
	re := regexp.MustCompile(regex)
	return re.ReplaceAllString(domain, "")
}

func (a *Agent) processDNSLayer(dns *layers.DNS) uint8 {
	if !dns.QR {
		return a.processDNSQuery(dns)
	}
	return a.processDNSResponse(dns)
}

func (a *Agent) processDNSQuery(dns *layers.DNS) uint8 {
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
			a.addConnectionLog(ConnectionLog{
				Decision: "allowed",
				Protocol: "DNS",
				SrcIP:    "unknown",
				DstIP:    "unknown",
				DstPort:  "53",
				Domain:   domain,
				Reason:   "domain-allowed",
			})
			return ACCEPT_REQUEST
		}

		fmt.Printf("%s -> Blocked DNS Query\n", domain)
		a.addConnectionLog(ConnectionLog{
			Decision: "blocked",
			Protocol: "DNS",
			SrcIP:    "unknown",
			DstIP:    "unknown",
			DstPort:  "53",
			Domain:   domain,
			Reason:   "domain-not-allowed",
		})
		return DROP_REQUEST
	}
	return DROP_REQUEST
}

func (a *Agent) processDNSTypeAResponse(domain string, answer *layers.DNSResourceRecord) {
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
			a.addConnectionLog(ConnectionLog{
				Decision: "allowed",
				Protocol: "DNS-response",
				SrcIP:    "unknown",
				DstIP:    ip,
				DstPort:  "53",
				Domain:   domain,
				Reason:   "dns-resolved",
			})
		}
	} else if a.isIpAllowed(ip) {
		fmt.Println("-> Allowed request")
		a.addConnectionLog(ConnectionLog{
			Decision: "allowed",
			Protocol: "DNS-response",
			SrcIP:    "unknown",
			DstIP:    ip,
			DstPort:  "53",
			Domain:   domain,
			Reason:   "ip-allowed",
		})
	} else {
		a.addConnectionLog(ConnectionLog{
			Decision: "blocked",
			Protocol: "DNS-response",
			SrcIP:    "unknown",
			DstIP:    ip,
			DstPort:  "53",
			Domain:   domain,
			Reason:   "domain-not-allowed",
		})
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

func (a *Agent) processDNSResponse(dns *layers.DNS) uint8 {
	domain := string(dns.Questions[0].Name)
	for _, answer := range dns.Answers {
		fmt.Printf("DNS Answer: %s %s %s\n", answer.Name, answer.Type, answer.IP)
		if answer.Type == layers.DNSTypeA {
			a.processDNSTypeAResponse(domain, &answer)
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

	domain := string(dns.Questions[0].Name)
	// if we are blocking DNS queries, intercept the DNS queries and decide whether to block or allow them
	if !dns.QR {
		// making sure the DNS query is using a trusted DNS server
		destinationIP, err := getDestinationIP(packet)
		if err != nil {
			fmt.Printf("Failed to get destination IP: %v\n", err)
			return DROP_REQUEST
		}
		if !a.allowedDNSServers[destinationIP] {
			fmt.Printf("%s -> Blocked DNS Query. Untrusted DNS server %s\n", domain, destinationIP)
			a.addConnectionLog(ConnectionLog{
				Decision: "blocked",
				Protocol: "DNS",
				SrcIP:    "unknown",
				DstIP:    destinationIP,
				DstPort:  "53",
				Domain:   domain,
				Reason:   "untrusted-dns-server",
			})
			return DROP_REQUEST
		}
	}

	// if we are not blocking DNS queries, just accept the query request
	if !a.blockDNS && !dns.QR {
		return ACCEPT_REQUEST
	}
	return a.processDNSLayer(dns)
}

func (a *Agent) processDNSOverTCPPayload(payload []byte) uint8 {
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
	return a.processDNSLayer(dns)
}

func (a *Agent) processTCPPacket(packet gopacket.Packet) uint8 {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcp, _ := tcpLayer.(*layers.TCP)
	dstPort, srcPort, payload := tcp.DstPort, tcp.SrcPort, tcp.Payload

	// Validate DNS server IP
	if dstPort == DNS_PORT {
		destinationIP, err := getDestinationIP(packet)
		if err != nil {
			fmt.Printf("Failed to get destination IP: %v\n", err)
			return DROP_REQUEST
		}
		if !a.allowedDNSServers[destinationIP] {
			fmt.Printf("%s -> Blocked DNS Query. Untrusted DNS server %s\n", "unknown", destinationIP)
			a.addConnectionLog(ConnectionLog{
				Decision: "blocked",
				Protocol: "TCP-DNS",
				SrcIP:    "unknown",
				DstIP:    destinationIP,
				DstPort:  "53",
				Domain:   "unknown",
				Reason:   "untrusted-dns-server",
			})
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
	return a.processDNSOverTCPPayload(payload)

}

func (a *Agent) processNonDNSPacket(packet gopacket.Packet) uint8 {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		fmt.Println("No network layer found, dropping packet")
		a.addConnectionLog(ConnectionLog{
			Decision: "blocked",
			Protocol: "unknown",
			SrcIP:    "unknown",
			DstIP:    "unknown",
			DstPort:  "unknown",
			Domain:   "unknown",
			Reason:   "no-network-layer",
		})
		return DROP_REQUEST
	}

	var srcIP, dstIP, protocol string
	var srcPort, dstPort string = "N/A", "N/A"

	// Extract IP addresses
	switch v := netLayer.(type) {
	case *layers.IPv4:
		srcIP = v.SrcIP.String()
		dstIP = v.DstIP.String()
		protocol = v.Protocol.String()
	case *layers.IPv6:
		srcIP = v.SrcIP.String()
		dstIP = v.DstIP.String()
		protocol = v.NextHeader.String()
	default:
		fmt.Println("Unknown network layer type, dropping packet")
		a.addConnectionLog(ConnectionLog{
			Decision: "blocked",
			Protocol: "unknown",
			SrcIP:    "unknown",
			DstIP:    "unknown",
			DstPort:  "unknown",
			Domain:   "unknown",
			Reason:   "unknown-network-layer",
		})
		return DROP_REQUEST
	}

	// Extract ports if TCP or UDP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort = tcp.SrcPort.String()
		dstPort = tcp.DstPort.String()
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort = udp.SrcPort.String()
		dstPort = udp.DstPort.String()
	}

	// Look up domain for this IP (if it was resolved via DNS)
	domain, hasDomain := a.ipToDomain[dstIP]
	if !hasDomain {
		domain = "unknown"
	}

	// Check if destination IP is allowed
	if a.isIpAllowed(dstIP) {
		fmt.Printf("ALLOW: %s:%s -> %s:%s (%s) [%s]\n", srcIP, srcPort, dstIP, dstPort, protocol, domain)
		a.addConnectionLog(ConnectionLog{
			Decision: "allowed",
			Protocol: protocol,
			SrcIP:    srcIP,
			DstIP:    dstIP,
			DstPort:  dstPort,
			Domain:   domain,
			Reason:   "ip-allowed",
		})
		return ACCEPT_REQUEST
	}

	// In audit mode, log but allow
	if !a.blocking {
		fmt.Printf("AUDIT: %s:%s -> %s:%s (%s) [%s] - would be blocked\n", srcIP, srcPort, dstIP, dstPort, protocol, domain)
		a.addConnectionLog(ConnectionLog{
			Decision: "audit",
			Protocol: protocol,
			SrcIP:    srcIP,
			DstIP:    dstIP,
			DstPort:  dstPort,
			Domain:   domain,
			Reason:   "ip-not-allowed",
		})
		return ACCEPT_REQUEST
	}

	// Block mode - drop the packet
	fmt.Printf("BLOCK: %s:%s -> %s:%s (%s) [%s]\n", srcIP, srcPort, dstIP, dstPort, protocol, domain)
	a.addConnectionLog(ConnectionLog{
		Decision: "blocked",
		Protocol: protocol,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		DstPort:  dstPort,
		Domain:   domain,
		Reason:   "ip-not-allowed",
	})
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
