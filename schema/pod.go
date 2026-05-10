package schema

import "text/template"

// GetPodOptions generates all pod schema options
func GetPodOptions() []SchemaOption {
	options := []SchemaOption{
		optPodName(),
		optServiceName(),
		optExitPolicy(),
		optPublishPortPod(),
		optHostNamePod(),
		optDNSPod(),
		optDNSOptionPod(),
		optDNSSearchPod(),
		optAddHostPod(),
		optNetworkAliasPod(),
		optIPPod(),
		optIP6Pod(),
		optNetworkPod(),
		optShmSizePod(),
		optUserNSPod(),
		optUIDMapPod(),
		optGIDMapPod(),
		optSubUIDMapPod(),
		optSubGIDMapPod(),
		optVolumePod(),
		optLabelPod(),
		optPodmanArgsPod(),
		optGlobalArgsPod(),
		optContainersConfModulePod(),
	}

	// Pre-parse templates for all options to catch errors early. Will panic if any template is invalid, which is desirable during development.
	for i, option := range options {
		options[i].QuadletTemplateParsed = template.Must(template.New("quadlet").Parse(option.QuadletTemplate))
		options[i].PodmanTemplateParsed = template.Must(template.New("podman").Parse(option.PodmanTemplate))
	}

	return options
}

// Helper functions for pod options
func optPodName() SchemaOption {
	return SchemaOption{
		QuadletKey:      "PodName",
		PodmanKey:       "--name",
		Description:     "The (optional) name of the Podman pod. Default is systemd-<unitname> to avoid conflicts with user-managed pods.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optServiceName() SchemaOption {
	return SchemaOption{
		QuadletKey:      "ServiceName",
		PodmanKey:       "service",
		Description:     "By default, the systemd service unit is named by appending '-pod' to the unit name. Set this to override.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optExitPolicy() SchemaOption {
	return SchemaOption{
		QuadletKey:      "ExitPolicy",
		PodmanKey:       "--exit-policy",
		Description:     "Set the exit policy of the pod when the last container exits. Default for Quadlets is 'stop'.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "stop", Description: "Stop the pod (default)"},
			{Value: "continue", Description: "Keep the pod active"},
		},
	}
}

func optPublishPortPod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "PublishPort",
		PodmanKey:       "--publish",
		Description:     "Publish a pod's port to the host. Format: [[ip:][hostPort]:]containerPort[/protocol]. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optHostNamePod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "HostName",
		PodmanKey:       "--hostname",
		Description:     "Set the pod's hostname. Only works with private UTS namespace. Added to /etc/hosts with pod's primary IP.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optDNSPod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "DNS",
		PodmanKey:       "--dns",
		Description:     "Set custom DNS servers for all containers in the pod. Can be specified multiple times. Use 'none' to disable /etc/resolv.conf creation.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optDNSOptionPod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "DNSOption",
		PodmanKey:       "--dns-option",
		Description:     "Set custom DNS options for the pod. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optDNSSearchPod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "DNSSearch",
		PodmanKey:       "--dns-search",
		Description:     "Set custom DNS search domains for the pod. Use DNSSearch=. to remove search domain.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optAddHostPod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "AddHost",
		PodmanKey:       "--add-host",
		Description:     "Add a custom host-to-IP mapping to /etc/hosts. Format: hostname[;hostname[;...]]:ip or use 'host-gateway'.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optNetworkAliasPod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "NetworkAlias",
		PodmanKey:       "--network-alias",
		Description:     "Add a network-scoped alias for all containers in the pod across all networks.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optIPPod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "IP",
		PodmanKey:       "--ip",
		Description:     "Specify a static IPv4 address for the pod. Must be within network IP pool when using single network.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optIP6Pod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "IP6",
		PodmanKey:       "--ip6",
		Description:     "Specify a static IPv6 address for the pod. Must be within network IPv6 pool when using single network.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optNetworkPod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Network",
		PodmanKey:       "--network",
		Description:     "Set the network mode for all containers in the pod. Special case: if name ends with .network, uses Podman network called systemd-$name.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "bridge", Description: "Create a network stack on default bridge"},
			{Value: "host", Description: "Use the host's network namespace"},
			{Value: "none", Description: "No network interfaces configured"},
			{Value: "pasta", Description: "Use pasta for user-mode networking (rootless default)"},
		},
	}
}

func optShmSizePod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "ShmSize",
		PodmanKey:       "--shm-size",
		Description:     "Size of /dev/shm for all containers. Units: b (bytes), k (kibibytes), m (mebibytes), g (gibibytes). Default: 64m.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optUserNSPod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "UserNS",
		PodmanKey:       "--userns",
		Description:     "Set the user namespace mode for all containers in the pod.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "auto", Description: "Automatically create namespace"},
			{Value: "host", Description: "Use host namespace (default)"},
			{Value: "keep-id", Description: "Map current user to same UID"},
			{Value: "nomap", Description: "Do not map current user"},
		},
	}
}

func optUIDMapPod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "UIDMap",
		PodmanKey:       "--uidmap",
		Description:     "Run all containers in pod with UID mapping. Format: container_uid:from_uid[:amount]. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optGIDMapPod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "GIDMap",
		PodmanKey:       "--gidmap",
		Description:     "Run all containers in pod with GID mapping. Format: container_gid:from_gid[:amount]. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optSubUIDMapPod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "SubUIDMap",
		PodmanKey:       "--subuidname",
		Description:     "Run containers in pod using the map with name in /etc/subuid.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optSubGIDMapPod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "SubGIDMap",
		PodmanKey:       "--subgidname",
		Description:     "Run containers in pod using the map with name in /etc/subgid.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optVolumePod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Volume",
		PodmanKey:       "--volume",
		Description:     "Create a bind mount or named volume for all containers in the pod. Format: [[SOURCE|HOST-DIR:]CONTAINER-DIR[:OPTIONS]]. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optLabelPod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Label",
		PodmanKey:       "--label",
		Description:     "Add metadata to the pod. Format: key=value. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optPodmanArgsPod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "PodmanArgs",
		PodmanKey:       "podman",
		Description:     "Arguments passed to end of 'podman pod create' command. Can be used for unsupported features.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optGlobalArgsPod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "GlobalArgs",
		PodmanKey:       "podman",
		Description:     "Arguments passed directly after 'podman' command. Can be used for unsupported features.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optContainersConfModulePod() SchemaOption {
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

// optPodSchema generates the complete pod schema
func optPodSchema() Schema {
	options := GetPodOptions()
	PopulateValidators(options)

	return Schema{
		{
			Type:    "Pod",
			Options: options,
		},
	}
}
