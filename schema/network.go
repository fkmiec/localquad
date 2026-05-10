package schema

import "text/template"

// GetNetworkOptions generates all network schema options
func GetNetworkOptions() []SchemaOption {
	options := []SchemaOption{
		optNetworkName(),
		optDriver(),
		optDisableDNS(),
		optDNSServer(),
		optGateway(),
		optIPRange(),
		optIPv6Network(),
		optIPAMDriver(),
		optInterfaceName(),
		optInternal(),
		optLabel(),
		optNetworkDeleteOnStop(),
		optSubnet(),
		optPodmanArgsNetwork(),
		optGlobalArgsNetwork(),
		optContainersConfModuleNetwork(),
	}

	// Pre-parse templates for all options to catch errors early. Will panic if any template is invalid, which is desirable during development.
	for i, option := range options {
		options[i].QuadletTemplateParsed = template.Must(template.New("quadlet").Parse(option.QuadletTemplate))
		options[i].PodmanTemplateParsed = template.Must(template.New("podman").Parse(option.PodmanTemplate))
	}

	return options
}

// Helper functions for network options
func optNetworkName() SchemaOption {
	return SchemaOption{
		QuadletKey:      "NetworkName",
		PodmanKey:       "--name",
		Description:     "The (optional) name of the Podman network. Default is systemd-<unitname> to avoid conflicts.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optDriver() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Driver",
		PodmanKey:       "--driver",
		Description:     "Driver to manage the network. Supports: bridge (default), macvlan, ipvlan, and netavark plugins.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "bridge", Description: "Bridge driver (default)"},
			{Value: "macvlan", Description: "Macvlan driver"},
			{Value: "ipvlan", Description: "IPvlan driver"},
		},
	}
}

func optDisableDNS() SchemaOption {
	return SchemaOption{
		QuadletKey:      "DisableDNS",
		PodmanKey:       "--disable-dns",
		Description:     "Disable the DNS plugin for this network. Only supported with bridge driver.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--disable-dns",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Disable DNS plugin"},
		},
	}
}

func optDNSServer() SchemaOption {
	return SchemaOption{
		QuadletKey:      "DNS",
		PodmanKey:       "--dns",
		Description:     "Set custom DNS servers for the network. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optGateway() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Gateway",
		PodmanKey:       "--gateway",
		Description:     "Define a gateway for the subnet. Requires Subnet= option. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optIPRange() SchemaOption {
	return SchemaOption{
		QuadletKey:      "IPRange",
		PodmanKey:       "--ip-range",
		Description:     "Allocate container IP from a range. Format: CIDR notation or <startIP>-<endIP>. Requires Subnet=. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optIPv6Network() SchemaOption {
	return SchemaOption{
		QuadletKey:      "IPv6",
		PodmanKey:       "--ipv6",
		Description:     "Enable IPv6 (Dual Stack) networking. If no subnets given, allocates IPv4 and IPv6 subnet.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--ipv6",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Enable IPv6"},
		},
	}
}

func optIPAMDriver() SchemaOption {
	return SchemaOption{
		QuadletKey:      "IPAMDriver",
		PodmanKey:       "--ipam-driver",
		Description:     "Set the IPAM driver for the network. Options: dhcp, host-local, none.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "dhcp", Description: "DHCP IP assignment (requires netavark-dhcp-proxy.socket or cni-dhcp.socket)"},
			{Value: "host-local", Description: "Local IP assignment"},
			{Value: "none", Description: "No IP assignment"},
		},
	}
}

func optInterfaceName() SchemaOption {
	return SchemaOption{
		QuadletKey:      "InterfaceName",
		PodmanKey:       "--interface-name",
		Description:     "Specify network interface name. For bridge: bridge name. For macvlan/ipvlan: parent host device.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optInternal() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Internal",
		PodmanKey:       "--internal",
		Description:     "Restrict external access of this network. No default route added to containers.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--internal",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Restrict external access"},
		},
	}
}

func optDriverSpecificOptions() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Options",
		PodmanKey:       "--opt",
		Description:     "Set driver specific options. All drivers support: mtu, metric, no_default_route. Bridge-specific: vlan, isolate, com.docker.network.bridge.name, vrf. Macvlan/ipvlan: parent, mode, bclim.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optSubnet() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Subnet",
		PodmanKey:       "--subnet",
		Description:     "The subnet in CIDR notation. Can be specified multiple times for multiple subnets. Useful for static IPv4 and IPv6 subnets.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optPodmanArgsNetwork() SchemaOption {
	return SchemaOption{
		QuadletKey:      "PodmanArgs",
		PodmanKey:       "podman",
		Description:     "Arguments passed to end of 'podman network create' command.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optGlobalArgsNetwork() SchemaOption {
	return SchemaOption{
		QuadletKey:      "GlobalArgs",
		PodmanKey:       "podman",
		Description:     "Arguments passed directly after 'podman' command.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optContainersConfModuleNetwork() SchemaOption {
	return SchemaOption{
		QuadletKey:      "ContainersConfModule",
		PodmanKey:       "--module",
		Description:     "Load a containers.conf module. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

// optNetworkSchema generates the complete network schema
func optNetworkSchema() Schema {
	options := GetNetworkOptions()
	PopulateValidators(options)

	return Schema{
		{
			Type:    "Network",
			Options: options,
		},
	}
}

func optNetworkDeleteOnStop() SchemaOption {
	return SchemaOption{
		QuadletKey:      "DeleteOnStop",
		PodmanKey:       "--delete-on-stop",
		Description:     "Delete the network when the last container using it stops.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--delete-on-stop",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Delete network on last container stop"},
		},
	}
}
