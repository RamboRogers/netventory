package views

// Interface represents a network interface
type Interface struct {
	Name         string
	IPAddress    string
	SubnetMask   string
	CIDR         string
	MACAddress   string
	Gateway      string
	IsUp         bool
	Priority     int
	FriendlyName string // For Windows display names
}
