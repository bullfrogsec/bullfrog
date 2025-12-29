package types

// SocketEntry represents a parsed line from /proc/net/{tcp,udp}
type SocketEntry struct {
	LocalAddr  string // Hex format: "0100007F:0277"
	RemoteAddr string
	State      string
	Inode      uint64
}
