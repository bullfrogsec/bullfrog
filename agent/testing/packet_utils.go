package testing

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

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