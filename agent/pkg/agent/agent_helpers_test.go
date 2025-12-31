package agent

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Mock implementations for testing

type mockNetInfoProvider struct {
}

func (m *mockNetInfoProvider) GetDNSServer() (string, error) {
	return "127.0.0.125", nil
}

func (m *mockNetInfoProvider) FlushDNSCache() error {
	return nil
}

type mockFileSystem struct {
}

func (m *mockFileSystem) Append(filename string, content string) error {
	return nil
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
