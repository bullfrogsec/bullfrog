package testing

type NetInfoProvider struct {
}

func (m *NetInfoProvider) GetDNSServer() (string, error) {
	return "127.0.0.125", nil
}

func (m *NetInfoProvider) FlushDNSCache() error {
	return nil
}

type FileSystem struct {
}

func (m *FileSystem) Append(filename string, content string) error {
	return nil
}
