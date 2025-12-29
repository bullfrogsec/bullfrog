package testing

import (
	"fmt"

	"github.com/bullfrogsec/agent/types"
)

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

type ProcProvider struct {
	InodeToPID    map[uint64]int
	PIDToName     map[int]string
	PIDToCmdLine  map[int]string
	PIDToExecPath map[int]string
}

func NewMockProcProvider() *ProcProvider {
	return &ProcProvider{
		InodeToPID:    make(map[uint64]int),
		PIDToName:     make(map[int]string),
		PIDToCmdLine:  make(map[int]string),
		PIDToExecPath: make(map[int]string),
	}
}

// ReadProcNetFile returns an empty slice for testing - tests don't need actual socket data
func (m *ProcProvider) ReadProcNetFile(protocol string, ipVersion int) ([]types.SocketEntry, error) {
	return []types.SocketEntry{}, nil
}

func (m *ProcProvider) FindProcessByInode(inode uint64) (int, error) {
	if pid, ok := m.InodeToPID[inode]; ok {
		return pid, nil
	}
	return 0, fmt.Errorf("inode not found")
}

func (m *ProcProvider) GetProcessName(pid int) (string, error) {
	if name, ok := m.PIDToName[pid]; ok {
		return name, nil
	}
	return "", fmt.Errorf("process not found")
}

func (m *ProcProvider) GetCommandLine(pid int) (string, error) {
	if cmdLine, ok := m.PIDToCmdLine[pid]; ok {
		return cmdLine, nil
	}
	return "", fmt.Errorf("command line not found")
}

func (m *ProcProvider) GetExecutablePath(pid int) (string, error) {
	if execPath, ok := m.PIDToExecPath[pid]; ok {
		return execPath, nil
	}
	return "", fmt.Errorf("executable path not found")
}

func (m *ProcProvider) GetProcesses() ([]int, error) {
	var pids []int
	for pid := range m.PIDToName {
		pids = append(pids, pid)
	}
	return pids, nil
}

// ContainerInfo holds container information (duplicated for testing independence)
type ContainerInfo struct {
	ID      string
	Name    string
	Image   string
	RootPID int
}

// ProcessDetails holds process information for mock Docker provider
type ProcessDetails struct {
	PID         int
	ProcessName string
	CommandLine string
	ExecPath    string
}

// MockDockerProvider implements IDockerProvider for testing
type MockDockerProvider struct {
	Containers map[string]*ContainerInfo  // Key: IP address
	ProcessMap map[string]*ProcessDetails // Key: "containerID:IP:Port:Protocol"
}

func NewMockDockerProvider() *MockDockerProvider {
	return &MockDockerProvider{
		Containers: make(map[string]*ContainerInfo),
		ProcessMap: make(map[string]*ProcessDetails),
	}
}

func (m *MockDockerProvider) FindContainerByIP(ip string) (*ContainerInfo, error) {
	if container, exists := m.Containers[ip]; exists {
		return container, nil
	}
	return nil, fmt.Errorf("container not found")
}

func (m *MockDockerProvider) GetProcessInContainer(container *ContainerInfo, srcIP, srcPort, protocol string) (
	int, string, string, string, error) {

	key := fmt.Sprintf("%s:%s:%s:%s", container.ID, srcIP, srcPort, protocol)
	if proc, exists := m.ProcessMap[key]; exists {
		return proc.PID, proc.ProcessName, proc.CommandLine, proc.ExecPath, nil
	}
	return 0, "", "", "", fmt.Errorf("process not found")
}

func (m *MockDockerProvider) Close() error {
	return nil
}
