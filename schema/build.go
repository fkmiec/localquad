package schema

import "text/template"

// GenerateBuildOptions generates all build schema options
func GetBuildOptions() []SchemaOption {
	options := []SchemaOption{
		optFile(),
		optBuildImageTag(),
		optArchBuild(),
		optOSBuild(),
		optVariantBuild(),
		optTarget(),
		optAnnotationBuild(),
		optEnvironmentBuild(),
		optLabel(),
		optDNSBuild(),
		optDNSOptionBuild(),
		optDNSSearchBuild(),
		optNetworkBuild(),
		optVolumeBuild(),
		optAuthFileBuild(),
		optCertDirBuild(),
		optCredsImage(),
		optDecryptionKeyBuild(),
		optForceRM(),
		optBuildGroupAdd(),
		optBuildPull(),
		optRetryBuild(),
		optRetryDelayBuild(),
		optSecretBuild(),
		optSetWorkingDirectoryBuild(),
		optTLSVerifyBuild(),
		optPodmanArgsBuild(),
		optGlobalArgsBuild(),
		optContainersConfModuleBuild(),
	}

	// Pre-parse templates for all options to catch errors early. Will panic if any template is invalid, which is desirable during development.
	for i, option := range options {
		options[i].QuadletTemplateParsed = template.Must(template.New("quadlet").Parse(option.QuadletTemplate))
		options[i].PodmanTemplateParsed = template.Must(template.New("podman").Parse(option.PodmanTemplate))
	}

	return options
}

// Helper functions for build options
func optFile() SchemaOption {
	return SchemaOption{
		QuadletKey:      "File",
		PodmanKey:       "--file",
		Description:     "Path to the Dockerfile or Containerfile. Default: Containerfile or Dockerfile in working directory.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optBuildImageTag() SchemaOption {
	return SchemaOption{
		QuadletKey:      "ImageTag",
		PodmanKey:       "--tag",
		Description:     "Name and optionally tag (name:tag). Can be specified multiple times to create multiple tags.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optArchBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Arch",
		PodmanKey:       "--arch",
		Description:     "Set TARGETARCH environment variable to this value. Default: host architecture.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "amd64", Description: "AMD64 architecture"},
			{Value: "arm64", Description: "ARM64 architecture"},
			{Value: "arm", Description: "ARM architecture"},
			{Value: "ppc64le", Description: "PowerPC64 LE"},
			{Value: "s390x", Description: "IBM Z architecture"},
		},
	}
}

func optOSBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "OS",
		PodmanKey:       "--os",
		Description:     "Set TARGETOS environment variable to this value. Default: host OS.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "linux", Description: "Linux OS"},
			{Value: "windows", Description: "Windows OS"},
		},
	}
}

func optVariantBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Variant",
		PodmanKey:       "--variant",
		Description:     "Set TARGETVARIANT environment variable (e.g., v6, v7, v8) for ARM images.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "v6", Description: "ARM v6"},
			{Value: "v7", Description: "ARM v7"},
			{Value: "v8", Description: "ARM v8"},
		},
	}
}

func optTarget() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Target",
		PodmanKey:       "--target",
		Description:     "Build specified target stage in multistage builds.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optAnnotationBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Annotation",
		PodmanKey:       "--annotation",
		Description:     "Set metadata annotations on the built image. Format: key=value. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optEnvironmentBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Environment",
		PodmanKey:       "--build-arg",
		Description:     "Set build-time environment variable for Dockerfile/Containerfile. Format: key=value or key (from container env). Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optLabelBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Label",
		PodmanKey:       "--label",
		Description:     "Add OCI labels to the built image. Format: key=value. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optDNSBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "DNS",
		PodmanKey:       "--dns",
		Description:     "Set custom DNS servers for build containers. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optDNSOptionBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "DNSOption",
		PodmanKey:       "--dns-option",
		Description:     "Set custom DNS options for build containers. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optDNSSearchBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "DNSSearch",
		PodmanKey:       "--dns-search",
		Description:     "Set custom DNS search domains for build containers. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optNetworkBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Network",
		PodmanKey:       "--network",
		Description:     "Set network mode for build containers. Default: host. Special case: if name ends with .network, uses systemd-$name.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "bridge", Description: "Bridge network"},
			{Value: "host", Description: "Host network (default)"},
			{Value: "none", Description: "No network"},
			{Value: "pasta", Description: "User-mode networking"},
		},
	}
}

func optVolumeBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Volume",
		PodmanKey:       "--volume",
		Description:     "Bind mount for build containers. Format: [[SOURCE|HOST-DIR:]CONTAINER-DIR[:OPTIONS]]. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optAuthFileBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "AuthFile",
		PodmanKey:       "--authfile",
		Description:     "Path to authentication file. Default: ${XDG_RUNTIME_DIR}/containers/auth.json (Linux) or $HOME/.config/containers/auth.json (Windows/macOS).",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optCertDirBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "CertDir",
		PodmanKey:       "--cert-dir",
		Description:     "Use certificates at path (*.crt, *.cert, *.key) to connect to registry. Default: /etc/containers/certs.d.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optCredsImage() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Creds",
		PodmanKey:       "--creds",
		Description:     "Credentials for registry. Format: [username[:password]]. Password entered without echo if not supplied.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optDecryptionKeyBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "DecryptionKey",
		PodmanKey:       "--decryption-key",
		Description:     "Key for decryption of images. Format: [key[:passphrase]].",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optForceRM() SchemaOption {
	return SchemaOption{
		QuadletKey:      "ForceRM",
		PodmanKey:       "--force-rm",
		Description:     "Always remove intermediate containers, even on build failure.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--force-rm",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Force remove intermediate containers"},
		},
	}
}

func optBuildGroupAdd() SchemaOption {
	return SchemaOption{
		QuadletKey:      "GroupAdd",
		PodmanKey:       "--group-add",
		Description:     "Add additional groups for build containers. Format: group name or GID. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optBuildPull() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Pull",
		PodmanKey:       "--pull",
		Description:     "Set pull policy for base images. Options: always (default), missing, never, newer.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "always", Description: "Always pull"},
			{Value: "missing", Description: "Pull if missing"},
			{Value: "never", Description: "Never pull"},
			{Value: "newer", Description: "Pull if newer available"},
		},
	}
}

func optRetryBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Retry",
		PodmanKey:       "--retry",
		Description:     "Number of times to retry pulling images in case of failure. Default: 3.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optRetryDelayBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "RetryDelay",
		PodmanKey:       "--retry-delay",
		Description:     "Duration of delay between retry attempts. Default: 2s with exponential backoff unless explicitly set.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optSecretBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Secret",
		PodmanKey:       "--secret",
		Description:     "Secret file to pass to build. Format: id=name,src=path. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optSetWorkingDirectoryBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "SetWorkingDirectory",
		PodmanKey:       "WorkingDirectory",
		Description:     "Set WorkingDirectory in systemd service. Options: containerfile (Containerfile/Dockerfile location), current (unit file location).",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "WorkingDirectory={{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "containerfile", Description: "Set to Containerfile/Dockerfile directory"},
			{Value: "current", Description: "Set to current/unit directory"},
		},
	}
}

func optTLSVerifyBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "TLSVerify",
		PodmanKey:       "--tls-verify",
		Description:     "Require HTTPS and verify certificates. Default: true. Can be overridden for insecure registries in containers-registries.conf.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Verify TLS certificates"},
			{Value: "false", Description: "Do not verify TLS certificates"},
		},
	}
}

func optPodmanArgsBuild() SchemaOption {
	return SchemaOption{
		QuadletKey:      "PodmanArgs",
		PodmanKey:       "podman",
		Description:     "Arguments passed to end of 'podman build' command.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optGlobalArgsBuild() SchemaOption {
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

func optContainersConfModuleBuild() SchemaOption {
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

// optBuildSchema generates the complete build schema
func GetBuildSchema() Schema {
	options := GetBuildOptions()
	PopulateValidators(options)

	return Schema{
		{
			Type:    "Build",
			Options: options,
		},
	}
}
