package testing

type Firewall struct {
	AllowedIPs map[string]bool
}

func NewFirewall() *Firewall {
	return &Firewall{
		AllowedIPs: make(map[string]bool),
	}
}

func (m *Firewall) AddIp(ip string) error {
	m.AllowedIPs[ip] = true
	return nil
}

type NetInfoProvider struct {
}

func (m *NetInfoProvider) GetDNSServer() (string, error) {
	return "127.0.0.125", nil
}

type FileSystem struct {
}

func (m *FileSystem) Append(filename string, content string) error {
	return nil
}
