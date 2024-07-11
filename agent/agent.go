package main

import (
	"fmt"
	"log"
	"net"
	"path"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	psutilnet "github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
)

var (
	blocking          = false
	defaultDomains    = []string{"github.com", "api.github.com", "*.actions.githubusercontent.com", "results-receiver.actions.githubusercontent.com", "*.blob.core.windows.net"}
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
)

type AgentConfig struct {
	EgressPolicy    string
	DNSPolicy       string
	AllowedDomains  []string
	AllowedIPs      []string
	Firewall        IFirewall
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
	firewall          IFirewall
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
		firewall:          config.Firewall,
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

	err := a.loadAllowedDNSServers()
	if err != nil {
		log.Fatalf("Loading DNS servers allowlist: %v", err)
	}

	err = a.addToFirewall(a.allowedIps, a.allowedCIDR)
	if err != nil {
		log.Fatalf("Error adding to firewall: %v", err)
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
			a.addIpToLogs("allowed", "unknown", ip)
			continue
		}
		fmt.Printf("Failed to parse IP: %s. Skipping.\n", ip)
	}
}

func (a *Agent) addToFirewall(ips map[string]bool, cidr []*net.IPNet) error {
	if !a.blocking {
		return nil
	}
	for ip := range ips {
		err := a.firewall.AddIp(ip)
		if err != nil {
			return fmt.Errorf("Error adding %s to firewall: %v\n", ip, err)
		}
	}
	for _, c := range cidr {
		err := a.firewall.AddIp(c.String())
		if err != nil {
			return fmt.Errorf("Error adding %s to firewall: %v\n", c.String(), err)
		}
	}
	return nil
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

func (a *Agent) addIpToLogs(decision string, domain string, ip string) {
	content := fmt.Sprintf("%d|%s|%s|%s\n", time.Now().UnixMilli(), decision, domain, ip)
	a.filesystem.Append("/var/log/gha-agent/decisions.log", content)
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

func (a *Agent) getDestinationIP(packet gopacket.Packet) (string, error) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
	}
	if ipLayer == nil {
		return "", fmt.Errorf("Failed to get IP layer")
	}
	ip, _ := ipLayer.(*layers.IPv4)
	if ip == nil {
		ip6, _ := ipLayer.(*layers.IPv6)
		if ip6 == nil {
			return "", fmt.Errorf("Failed to get IP layer")
		}
		return ip6.DstIP.String(), nil
	}
	return ip.DstIP.String(), nil
}

func (a *Agent) processDNSQuery(packet gopacket.Packet) uint8 {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	dns, _ := dnsLayer.(*layers.DNS)
	for _, q := range dns.Questions {
		domain := string(q.Name)
		fmt.Printf("DNS Question: %s %s\n", q.Name, q.Type)
		fmt.Print(domain)

		// making sure the DNS query is using a trusted DNS server
		destinationIP, err := a.getDestinationIP(packet)
		if err != nil {
			fmt.Println("Failed to get destination IP")
			a.addIpToLogs("blocked", domain, "unknown")
			return DROP_REQUEST
		}
		if !a.allowedDNSServers[destinationIP] {
			fmt.Printf("-> Blocked DNS Query. Untrusted DNS server %s\n", destinationIP)
			a.addIpToLogs("blocked", domain, "unknown")
			return DROP_REQUEST
		}

		if a.isDomainAllowed(domain) {
			fmt.Println("-> Allowed DNS Query")
			return ACCEPT_REQUEST
		}
		fmt.Println("-> Blocked DNS Query")
		a.addIpToLogs("blocked", domain, "unknown")
		return DROP_REQUEST
	}
	return DROP_REQUEST
}

func (a *Agent) processDNSTypeAResponse(domain string, answer *layers.DNSResourceRecord) {
	fmt.Printf("DNS Answer: %s %s %s\n", answer.Name, answer.Type, answer.IP)
	fmt.Printf("%s:%s", answer.Name, answer.IP)
	ip := answer.IP.String()
	if a.isDomainAllowed(domain) {
		fmt.Println("-> Allowed request")
		if !a.allowedIps[ip] {
			err := a.firewall.AddIp(ip)
			a.addIpToLogs("allowed", domain, ip)
			if err != nil {
				fmt.Printf("failed to add %s to firewall", ip)
			} else {
				a.allowedIps[ip] = true
			}
		}
	} else if a.isIpAllowed(ip) {
		fmt.Println("-> Allowed request")
		a.addIpToLogs("allowed", domain, ip)
	} else {
		a.addIpToLogs("blocked", domain, ip)
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

func (a *Agent) processDNSResponse(packet gopacket.Packet) uint8 {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	dns, _ := dnsLayer.(*layers.DNS)
	domain := string(dns.Questions[0].Name)
	for _, answer := range dns.Answers {
		if answer.Type == layers.DNSTypeA {
			a.processDNSTypeAResponse(domain, &answer)
		} else if answer.Type == layers.DNSTypeCNAME {
			a.processDNSTypeCNAMEResponse(domain, &answer)
		}
	}
	return ACCEPT_REQUEST
}

func (a *Agent) ProcessPacket(packet gopacket.Packet) uint8 {
	sourcePort, dstPort, err := getPorts(packet)
	if err != nil {
		fmt.Printf("Failed to get ports: %v\n", err)
	}
	fmt.Printf("Source Port: %d, Destination Port: %d\n", sourcePort, dstPort)
	err = printProcInfoByPort(sourcePort)
	if err != nil {
		fmt.Printf("Failed to get process info: %v\n", err)
	}

	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {

		dns, _ := dnsLayer.(*layers.DNS)
		for _, q := range dns.Questions {
			fmt.Printf("DNS Question: %s %s\n", q.Name, q.Type)
		}
		// if we are blocking DNS queries, intercept the DNS queries and decide whether to block or allow them
		if a.blockDNS && !dns.QR {
			return a.processDNSQuery(packet)
		} else if dns.QR {
			return a.processDNSResponse(packet)
		}
	} else {
		destIp, err := a.getDestinationIP(packet)
		if err != nil {
			fmt.Println("Failed to get destination IP")
			return DROP_REQUEST
		}

		fmt.Printf("Destination IP: %s\n", destIp)
		if a.isIpAllowed(destIp) {
			fmt.Printf("Allowed request to %s\n", destIp)
			a.addIpToLogs("allowed", "unknown", destIp)
			return ACCEPT_REQUEST
		} else {
			fmt.Printf("Blocked request to %s\n", destIp)
			a.addIpToLogs("blocked", "unknown", destIp)
			return DROP_REQUEST
		}
	}
	return ACCEPT_REQUEST
}

func getPorts(packet gopacket.Packet) (uint16, uint16, error) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp == nil {
			return 0, 0, fmt.Errorf("Failed to get TCP layer")
		}
		return uint16(tcp.SrcPort), uint16(tcp.DstPort), nil
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if udp == nil {
			return 0, 0, fmt.Errorf("Failed to get UDP layer")
		}
		return uint16(udp.SrcPort), uint16(udp.DstPort), nil
	}
	return 0, 0, fmt.Errorf("Failed to get TCP or UDP layer")
}

func getProcessByPort(port uint16) ([]*process.Process, error) {
	connections, err := psutilnet.Connections("inet")
	if err != nil {
		return nil, err
	}

	for _, conn := range connections {
		if uint16(conn.Laddr.Port) == port {
			pid := conn.Pid
			ancestors, err := getAncestorProcesses(pid)
			if err != nil {
				return nil, fmt.Errorf("Failed to get ancestor processes: %v\n", err)
			}
			var ancestorsProc []*process.Process
			for _, ancestor := range ancestors {
				proc, err := process.NewProcess(ancestor)
				if err != nil {
					return nil, fmt.Errorf("Failed to get process: %v\n", err)
				}
				ancestorsProc = append(ancestorsProc, proc)
			}
			return ancestorsProc, nil
		}
	}

	return nil, fmt.Errorf("no process found for port %d", port)
}

func printProcInfo(procs []*process.Process) error {
	fmt.Printf("ancestor processes:\n")
	if len(procs) == 0 {
		return fmt.Errorf("no process found")
	}
	for _, proc := range procs {

		cmdline, err := proc.Cmdline()
		if err != nil {
			log.Fatalf("Failed to get process command line: %v", err)
		}

		exe, err := proc.Exe()
		if err != nil {
			log.Fatalf("Failed to get process executable: %v", err)
		}

		cwd, err := proc.Cwd()
		if err != nil {
			log.Fatalf("Failed to get process working directory: %v", err)
		}

		fmt.Printf("\tcmdline: %s, exe: %s, cwd: %s\n", cmdline, exe, cwd)
	}
	return nil
}

func printProcInfoByPort(port uint16) error {
	procs, err := getProcessByPort(port)
	if err != nil {
		return err
	}
	return printProcInfo(procs)
}
