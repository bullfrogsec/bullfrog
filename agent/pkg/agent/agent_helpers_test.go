package agent

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Mock implementations for testing

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

type mockNetInfoProvider struct {
}

func (m *mockNetInfoProvider) GetDNSServer() (string, error) {
	return "127.0.0.125", nil
}

func (m *mockNetInfoProvider) FlushDNSCache() error {
	return nil
}

// mockNetInfoProviderIPv6 returns IPv6 localhost as DNS server
type mockNetInfoProviderIPv6 struct {
}

func (m *mockNetInfoProviderIPv6) GetDNSServer() (string, error) {
	return "::1", nil
}

func (m *mockNetInfoProviderIPv6) FlushDNSCache() error {
	return nil
}

type mockFileSystem struct {
	logs map[string][]string // filename -> array of logged entries
}

func newMockFileSystem() *mockFileSystem {
	return &mockFileSystem{
		logs: make(map[string][]string),
	}
}

func (m *mockFileSystem) Append(filename string, content string) error {
	if m.logs == nil {
		m.logs = make(map[string][]string)
	}
	m.logs[filename] = append(m.logs[filename], content)
	return nil
}

// GetLogs returns all log entries for a given file
func (m *mockFileSystem) GetLogs(filename string) []string {
	return m.logs[filename]
}

// GetLogCount returns the number of log entries for a given file
func (m *mockFileSystem) GetLogCount(filename string) int {
	return len(m.logs[filename])
}

// Clear clears all logs
func (m *mockFileSystem) Clear() {
	m.logs = make(map[string][]string)
}

type mockProcProvider struct {
	InodeToPID    map[uint64]int
	PIDToName     map[int]string
	PIDToCmdLine  map[int]string
	PIDToExecPath map[int]string
}

func newMockProcProvider() *mockProcProvider {
	return &mockProcProvider{
		InodeToPID:    make(map[uint64]int),
		PIDToName:     make(map[int]string),
		PIDToCmdLine:  make(map[int]string),
		PIDToExecPath: make(map[int]string),
	}
}

// ReadProcNetFile returns an empty slice for testing - tests don't need actual socket data
func (m *mockProcProvider) ReadProcNetFile(protocol string, ipVersion int) ([]SocketEntry, error) {
	return []SocketEntry{}, nil
}

func (m *mockProcProvider) FindProcessByInode(inode uint64) (int, error) {
	if pid, ok := m.InodeToPID[inode]; ok {
		return pid, nil
	}
	return 0, fmt.Errorf("inode not found")
}

func (m *mockProcProvider) GetProcessName(pid int) (string, error) {
	if name, ok := m.PIDToName[pid]; ok {
		return name, nil
	}
	return "", fmt.Errorf("process not found")
}

func (m *mockProcProvider) GetCommandLine(pid int) (string, error) {
	if cmdLine, ok := m.PIDToCmdLine[pid]; ok {
		return cmdLine, nil
	}
	return "", fmt.Errorf("command line not found")
}

func (m *mockProcProvider) GetExecutablePath(pid int) (string, error) {
	if execPath, ok := m.PIDToExecPath[pid]; ok {
		return execPath, nil
	}
	return "", fmt.Errorf("executable path not found")
}

func (m *mockProcProvider) GetProcesses() ([]int, error) {
	var pids []int
	for pid := range m.PIDToName {
		pids = append(pids, pid)
	}
	return pids, nil
}

// mockContainerInfo holds container information
type mockContainerInfo struct {
	ID      string
	Name    string
	Image   string
	RootPID int
}

// mockProcessDetails holds process information for mock Docker provider
type mockProcessDetails struct {
	PID         int
	ProcessName string
	CommandLine string
	ExecPath    string
}

// mockDockerProvider implements IDockerProvider for testing
type mockDockerProvider struct {
	Containers map[string]*mockContainerInfo  // Key: IP address
	ProcessMap map[string]*mockProcessDetails // Key: "containerID:IP:Port:Protocol"
}

func newMockDockerProvider() *mockDockerProvider {
	return &mockDockerProvider{
		Containers: make(map[string]*mockContainerInfo),
		ProcessMap: make(map[string]*mockProcessDetails),
	}
}

func (m *mockDockerProvider) FindContainerByIP(ip string) (*ContainerInfo, error) {
	if container, exists := m.Containers[ip]; exists {
		// Convert mock type to real type
		return &ContainerInfo{
			ID:      container.ID,
			Name:    container.Name,
			Image:   container.Image,
			RootPID: container.RootPID,
		}, nil
	}
	return nil, fmt.Errorf("container not found")
}

func (m *mockDockerProvider) GetProcessInContainer(container *ContainerInfo, srcIP, srcPort, protocol string) (
	int, string, string, string, error) {

	key := fmt.Sprintf("%s:%s:%s:%s", container.ID, srcIP, srcPort, protocol)
	if proc, exists := m.ProcessMap[key]; exists {
		return proc.PID, proc.ProcessName, proc.CommandLine, proc.ExecPath, nil
	}
	return 0, "", "", "", fmt.Errorf("process not found")
}

func (m *mockDockerProvider) Close() error {
	return nil
}

// mockProcProviderWithSockets extends mockProcProvider to return socket entries
type mockProcProviderWithSockets struct {
	mockProcProvider
}

func (m *mockProcProviderWithSockets) ReadProcNetFile(protocol string, ipVersion int) ([]SocketEntry, error) {
	// Convert 127.0.0.1:12345 to hex format
	// 127.0.0.1 = 0x7F000001 (little-endian: 0100007F)
	// 12345 = 0x3039 (hex for port)
	return []SocketEntry{
		{
			LocalAddr: "0100007F:3039",
			Inode:     12345,
		},
	}, nil
}

// mockProcProviderWithCallCount extends mockProcProviderWithSockets to track call counts
type mockProcProviderWithCallCount struct {
	mockProcProviderWithSockets
	callCount int
}

func (m *mockProcProviderWithCallCount) ReadProcNetFile(protocol string, ipVersion int) ([]SocketEntry, error) {
	m.callCount++
	return m.mockProcProviderWithSockets.ReadProcNetFile(protocol, ipVersion)
}

func GenerateDNSRequestPacket(domain string, nameserver net.IP) gopacket.Packet {
	dns := layers.DNS{
		ID:           0x22,
		QR:           false,
		OpCode:       layers.DNSOpCodeQuery,
		ResponseCode: layers.DNSResponseCodeNoErr,
		Questions: []layers.DNSQuestion{
			{
				Name: []byte(domain),
				Type: layers.DNSTypeA,
			},
		},
	}
	udp := layers.UDP{
		SrcPort: layers.UDPPort(1234),
		DstPort: layers.UDPPort(53),
	}
	ip := layers.IPv4{
		Protocol: layers.IPProtocolUDP, // must to decode next
		SrcIP:    net.IP{127, 0, 0, 1},
		DstIP:    nameserver,
		Version:  4,
	}
	return GenerateDNSPacket(dns, udp, ip)
}

func GenerateDNSTypeSRVRequestPacket(domain string, nameserver net.IP) gopacket.Packet {
	dns := layers.DNS{
		ID:           0x22,
		QR:           false,
		OpCode:       layers.DNSOpCodeQuery,
		ResponseCode: layers.DNSResponseCodeNoErr,
		Questions: []layers.DNSQuestion{
			{
				Name: []byte(domain),
				Type: layers.DNSTypeSRV,
			},
		},
	}
	udp := layers.UDP{
		SrcPort: layers.UDPPort(1234),
		DstPort: layers.UDPPort(53),
	}
	ip := layers.IPv4{
		Protocol: layers.IPProtocolUDP, // must to decode next
		SrcIP:    net.IP{127, 0, 0, 1},
		DstIP:    nameserver,
		Version:  4,
	}
	return GenerateDNSPacket(dns, udp, ip)
}

func GenerateDNSTypeAResponsePacket(domain string, answerIp net.IP, nameserver net.IP) gopacket.Packet {
	question := layers.DNSQuestion{
		Name: []byte(domain),
		Type: layers.DNSTypeA,
	}
	answer := layers.DNSResourceRecord{
		Name: []byte(domain),
		Type: layers.DNSTypeA,
		TTL:  60,
		IP:   answerIp,
	}
	return GenerateDNSResponsePacket(question, answer, nameserver)
}

func GenerateDNSTypeCNAMEResponsePacket(domain string, cname string, nameserver net.IP) gopacket.Packet {
	question := layers.DNSQuestion{
		Name: []byte(domain),
		Type: layers.DNSTypeCNAME,
	}
	answer := layers.DNSResourceRecord{
		Name:  []byte(domain),
		Type:  layers.DNSTypeCNAME,
		TTL:   60,
		CNAME: []byte(cname),
	}
	return GenerateDNSResponsePacket(question, answer, nameserver)
}

func GenerateDNSResponsePacket(question layers.DNSQuestion, answer layers.DNSResourceRecord, nameserver net.IP) gopacket.Packet {
	dns := layers.DNS{
		ID:           0x22,
		QR:           true,
		OpCode:       layers.DNSOpCodeQuery,
		ResponseCode: layers.DNSResponseCodeNoErr,
		Answers: []layers.DNSResourceRecord{
			answer,
		},
		Questions: []layers.DNSQuestion{question},
	}
	udp := layers.UDP{
		SrcPort: layers.UDPPort(53),
		DstPort: layers.UDPPort(1234),
	}
	ip := layers.IPv4{
		Protocol: layers.IPProtocolUDP, // must to decode next
		SrcIP:    nameserver,
		DstIP:    net.IP{127, 0, 0, 1},
		Version:  4,
	}
	return GenerateDNSPacket(dns, udp, ip)
}

func GenerateDNSPacket(dns layers.DNS, udp layers.UDP, ip layers.IPv4) gopacket.Packet {
	ether := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4, // must to decode next
		SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
	}
	udp.SetNetworkLayerForChecksum(&ip) //! REQUIRED for valid packet

	buf := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opt,
		&ether,
		&ip,
		&udp,
		&dns,
	)

	rawPacket := buf.Bytes()
	return gopacket.NewPacket(rawPacket, layers.LayerTypeEthernet, gopacket.Default)
}

// GenerateTCPPacket creates a TCP packet for testing non-DNS traffic
func GenerateTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) gopacket.Packet {
	ether := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
	}
	ip := layers.IPv4{
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Version:  4,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opt, &ether, &ip, &tcp)

	rawPacket := buf.Bytes()
	return gopacket.NewPacket(rawPacket, layers.LayerTypeEthernet, gopacket.Default)
}

// GenerateUDPPacket creates a UDP packet for testing non-DNS traffic
func GenerateUDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) gopacket.Packet {
	ether := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
	}
	ip := layers.IPv4{
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Version:  4,
	}
	udp := layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opt, &ether, &ip, &udp)

	rawPacket := buf.Bytes()
	return gopacket.NewPacket(rawPacket, layers.LayerTypeEthernet, gopacket.Default)
}

// GeneratePacketWithoutNetworkLayer creates a malformed packet without a network layer
func GeneratePacketWithoutNetworkLayer() gopacket.Packet {
	ether := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
	}

	buf := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opt, &ether)

	rawPacket := buf.Bytes()
	return gopacket.NewPacket(rawPacket, layers.LayerTypeEthernet, gopacket.Default)
}

// GenerateDNSOverTCPPacket creates a DNS query over TCP
func GenerateDNSOverTCPPacket(domain string, nameserver net.IP, withPayload bool) gopacket.Packet {
	ether := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
	}
	ip := layers.IPv4{
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{127, 0, 0, 1},
		DstIP:    nameserver,
		Version:  4,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(54321),
		DstPort: layers.TCPPort(53),
		SYN:     false,
		ACK:     true,
	}

	var payload []byte
	if withPayload {
		// Create DNS query
		dns := layers.DNS{
			ID:           0x1234,
			QR:           false,
			OpCode:       layers.DNSOpCodeQuery,
			ResponseCode: layers.DNSResponseCodeNoErr,
			Questions: []layers.DNSQuestion{
				{
					Name: []byte(domain),
					Type: layers.DNSTypeA,
				},
			},
		}

		// Serialize DNS message
		dnsBuf := gopacket.NewSerializeBuffer()
		dnsOpt := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: false,
		}
		dns.SerializeTo(dnsBuf, dnsOpt)
		dnsBytes := dnsBuf.Bytes()

		// Add length prefix (2 bytes, big-endian)
		dnsLen := uint16(len(dnsBytes))
		payload = make([]byte, 2+len(dnsBytes))
		payload[0] = byte(dnsLen >> 8)
		payload[1] = byte(dnsLen & 0xFF)
		copy(payload[2:], dnsBytes)
		tcp.Payload = payload
	}

	tcp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opt, &ether, &ip, &tcp, gopacket.Payload(payload))

	rawPacket := buf.Bytes()
	return gopacket.NewPacket(rawPacket, layers.LayerTypeEthernet, gopacket.Default)
}

// GenerateDNSOverTCPPacketWithInvalidPayload creates a DNS over TCP packet with invalid payload
func GenerateDNSOverTCPPacketWithInvalidPayload(nameserver net.IP) gopacket.Packet {
	ether := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
	}
	ip := layers.IPv4{
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{127, 0, 0, 1},
		DstIP:    nameserver,
		Version:  4,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(54321),
		DstPort: layers.TCPPort(53),
		SYN:     false,
		ACK:     true,
	}

	// Invalid payload: length says 100 bytes but only provide 5
	payload := []byte{0x00, 0x64, 0xFF, 0xFF, 0xFF}
	tcp.Payload = payload
	tcp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opt, &ether, &ip, &tcp, gopacket.Payload(payload))

	rawPacket := buf.Bytes()
	return gopacket.NewPacket(rawPacket, layers.LayerTypeEthernet, gopacket.Default)
}

// GenerateDNSOverTCPResponse creates a DNS response over TCP
func GenerateDNSOverTCPResponse(domain string, answerIP net.IP, nameserver net.IP) gopacket.Packet {
	ether := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
	}
	ip := layers.IPv4{
		Protocol: layers.IPProtocolTCP,
		SrcIP:    nameserver,
		DstIP:    net.IP{127, 0, 0, 1},
		Version:  4,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(53),
		DstPort: layers.TCPPort(54321),
		SYN:     false,
		ACK:     true,
	}

	// Create DNS response
	dns := layers.DNS{
		ID:           0x1234,
		QR:           true,
		OpCode:       layers.DNSOpCodeQuery,
		ResponseCode: layers.DNSResponseCodeNoErr,
		Questions: []layers.DNSQuestion{
			{
				Name: []byte(domain),
				Type: layers.DNSTypeA,
			},
		},
		Answers: []layers.DNSResourceRecord{
			{
				Name: []byte(domain),
				Type: layers.DNSTypeA,
				TTL:  60,
				IP:   answerIP,
			},
		},
	}

	// Serialize DNS message
	dnsBuf := gopacket.NewSerializeBuffer()
	dnsOpt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: false,
	}
	dns.SerializeTo(dnsBuf, dnsOpt)
	dnsBytes := dnsBuf.Bytes()

	// Add length prefix (2 bytes, big-endian)
	dnsLen := uint16(len(dnsBytes))
	payload := make([]byte, 2+len(dnsBytes))
	payload[0] = byte(dnsLen >> 8)
	payload[1] = byte(dnsLen & 0xFF)
	copy(payload[2:], dnsBytes)
	tcp.Payload = payload

	tcp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opt, &ether, &ip, &tcp, gopacket.Payload(payload))

	rawPacket := buf.Bytes()
	return gopacket.NewPacket(rawPacket, layers.LayerTypeEthernet, gopacket.Default)
}

// GenerateDNSTypeSRVResponsePacket creates a DNS SRV response
func GenerateDNSTypeSRVResponsePacket(domain string, target string, nameserver net.IP) gopacket.Packet {
	question := layers.DNSQuestion{
		Name: []byte(domain),
		Type: layers.DNSTypeSRV,
	}
	answer := layers.DNSResourceRecord{
		Name: []byte(domain),
		Type: layers.DNSTypeSRV,
		TTL:  60,
		SRV: layers.DNSSRV{
			Priority: 10,
			Weight:   20,
			Port:     443,
			Name:     []byte(target),
		},
	}
	return GenerateDNSResponsePacket(question, answer, nameserver)
}

// GenerateIPv6TCPPacket creates an IPv6 TCP packet
func GenerateIPv6TCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) gopacket.Packet {
	ether := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv6,
		SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
	}
	ip := layers.IPv6{
		NextHeader: layers.IPProtocolTCP,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		Version:    6,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opt, &ether, &ip, &tcp)

	rawPacket := buf.Bytes()
	return gopacket.NewPacket(rawPacket, layers.LayerTypeEthernet, gopacket.Default)
}

// GenerateIPv6UDPPacket creates an IPv6 UDP packet
func GenerateIPv6UDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) gopacket.Packet {
	ether := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv6,
		SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
	}
	ip := layers.IPv6{
		NextHeader: layers.IPProtocolUDP,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		Version:    6,
	}
	udp := layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opt, &ether, &ip, &udp)

	rawPacket := buf.Bytes()
	return gopacket.NewPacket(rawPacket, layers.LayerTypeEthernet, gopacket.Default)
}

// GenerateIPv6DNSRequestPacket creates an IPv6 DNS query
func GenerateIPv6DNSRequestPacket(domain string, nameserver net.IP) gopacket.Packet {
	dns := layers.DNS{
		ID:           0x22,
		QR:           false,
		OpCode:       layers.DNSOpCodeQuery,
		ResponseCode: layers.DNSResponseCodeNoErr,
		Questions: []layers.DNSQuestion{
			{
				Name: []byte(domain),
				Type: layers.DNSTypeA,
			},
		},
	}
	udp := layers.UDP{
		SrcPort: layers.UDPPort(1234),
		DstPort: layers.UDPPort(53),
	}
	ip := layers.IPv6{
		NextHeader: layers.IPProtocolUDP,
		SrcIP:      net.ParseIP("::1"),
		DstIP:      nameserver,
		Version:    6,
	}

	ether := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv6,
		SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
	}

	udp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opt, &ether, &ip, &udp, &dns)

	rawPacket := buf.Bytes()
	return gopacket.NewPacket(rawPacket, layers.LayerTypeEthernet, gopacket.Default)
}

// GenerateDNSTypeAAAAResponsePacket creates a DNS AAAA (IPv6) response
func GenerateDNSTypeAAAAResponsePacket(domain string, answerIP net.IP, nameserver net.IP) gopacket.Packet {
	question := layers.DNSQuestion{
		Name: []byte(domain),
		Type: layers.DNSTypeAAAA,
	}
	answer := layers.DNSResourceRecord{
		Name: []byte(domain),
		Type: layers.DNSTypeAAAA,
		TTL:  60,
		IP:   answerIP,
	}
	return GenerateDNSResponsePacket(question, answer, nameserver)
}
