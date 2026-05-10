package schema

import "text/template"

// GenerateKubeOptions generates all kube schema options
func GetKubeOptions() []SchemaOption {
	options := []SchemaOption{
		optYaml(),
		optAutoUpdate(),
		optConfigMap(),
		optExitCodePropagation(),
		optKubeDownForce(),
		optLogDriver(),
		optNetwork(),
		optPublishPort(),
		optSetWorkingDirectory(),
		optUserNS(),
		optPodmanArgsKube(),
		optGlobalArgsKube(),
		optContainersConfModuleKube(),
	}

	// Pre-parse templates for all options to catch errors early. Will panic if any template is invalid, which is desirable during development.
	for _, option := range options {
		option.QuadletTemplateParsed = template.Must(template.New("quadlet").Parse(option.QuadletTemplate))
		option.PodmanTemplateParsed = template.Must(template.New("podman").Parse(option.PodmanTemplate))
	}

	return options
}

// Helper functions for kube options
func optYaml() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Yaml",
		PodmanKey:       "file",
		Description:     "The path, absolute or relative to unit file, to the Kubernetes YAML file to use. This is the only required key.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optKubeAutoUpdate() SchemaOption {
	return SchemaOption{
		QuadletKey:      "AutoUpdate",
		PodmanKey:       "--annotation",
		Description:     "Indicate whether pods and containers from workload are auto-updated. Supports: registry (fully-qualified image), local (local image name), name/(local|registry) (specific container).",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--annotation io.containers.autoupdate={{.Value}}",
		AllowMultiple:   true,
		Values: []OptionValue{
			{Value: "registry", Description: "Auto-update from registry"},
			{Value: "local", Description: "Auto-update from local image"},
		},
	}
}

func optConfigMap() SchemaOption {
	return SchemaOption{
		QuadletKey:      "ConfigMap",
		PodmanKey:       "--configmap",
		Description:     "Use Kubernetes ConfigMap YAML to provide environment variable values. Path must be absolute or relative to unit file.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optExitCodePropagation() SchemaOption {
	return SchemaOption{
		QuadletKey:      "ExitCodePropagation",
		PodmanKey:       "service",
		Description:     "Control how main PID of systemd service exits. Options: all (all failed), any (any failed), none (ignore failures). Default: none.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "ExitCodePropagation={{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "all", Description: "Exit non-zero if all containers failed"},
			{Value: "any", Description: "Exit non-zero if any container failed"},
			{Value: "none", Description: "Always exit zero"},
		},
	}
}

func optKubeDownForce() SchemaOption {
	return SchemaOption{
		QuadletKey:      "KubeDownForce",
		PodmanKey:       "--force",
		Description:     "Remove all resources, including volumes, when calling 'podman kube down'.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--force",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Force remove all resources"},
		},
	}
}

func optKubeLogDriver() SchemaOption {
	return SchemaOption{
		QuadletKey:      "LogDriver",
		PodmanKey:       "--log-driver",
		Description:     "Logging driver for containers. Options: k8s-file, journald (default), none, passthrough, passthrough-tty.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "k8s-file", Description: "Kubernetes-style logging"},
			{Value: "journald", Description: "Systemd journal logging (default)"},
			{Value: "none", Description: "No logging"},
			{Value: "passthrough", Description: "Pass to stdout/stderr"},
			{Value: "passthrough-tty", Description: "Pass to TTY if available"},
		},
	}
}

func optKubeNetwork() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Network",
		PodmanKey:       "--network",
		Description:     "Set network mode for containers. Special case: if name ends with .network, uses Podman network systemd-$name.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "bridge", Description: "Default bridge network"},
			{Value: "host", Description: "Use host network"},
			{Value: "none", Description: "No network"},
			{Value: "pasta", Description: "User-mode networking (rootless default)"},
		},
	}
}

func optKubePublishPort() SchemaOption {
	return SchemaOption{
		QuadletKey:      "PublishPort",
		PodmanKey:       "--publish",
		Description:     "Publish container port to host. Format: [[ip:][hostPort]:]containerPort[/protocol]. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optSetWorkingDirectory() SchemaOption {
	return SchemaOption{
		QuadletKey:      "SetWorkingDirectory",
		PodmanKey:       "WorkingDirectory",
		Description:     "Set WorkingDirectory in systemd service. Supports: yaml (YAML file location), unit (unit file location).",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "WorkingDirectory={{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "yaml", Description: "Set to YAML file directory"},
			{Value: "unit", Description: "Set to unit file directory"},
		},
	}
}

func optKubeUserNS() SchemaOption {
	return SchemaOption{
		QuadletKey:      "UserNS",
		PodmanKey:       "--userns",
		Description:     "Set user namespace mode for containers.",
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

func optPodmanArgsKube() SchemaOption {
	return SchemaOption{
		QuadletKey:      "PodmanArgs",
		PodmanKey:       "podman",
		Description:     "Arguments passed to end of 'podman kube play' command.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optGlobalArgsKube() SchemaOption {
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

func optContainersConfModuleKube() SchemaOption {
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

// GetKubeSchema generates the complete kube schema
func GetKubeSchema() Schema {
	options := GetKubeOptions()
	PopulateValidators(options)

	return Schema{
		{
			Type:    "Kube",
			Options: options,
		},
	}
}
