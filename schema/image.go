package schema

import "text/template"

// GenerateImageOptions generates all image schema options
func GetImageOptions() []SchemaOption {
	options := []SchemaOption{
		optImageName(),
		optImageTag(),
		optAllTags(),
		optPolicy(),
		optArch(),
		optOS(),
		optVariant(),
		optAuthFile(),
		optCertDir(),
		optCreds(),
		optDecryptionKey(),
		optRetry(),
		optRetryDelay(),
		optTLSVerify(),
		optPodmanArgsImage(),
		optGlobalArgsImage(),
		optContainersConfModuleImage(),
	}

	// Pre-parse templates for all options to catch errors early. Will panic if any template is invalid, which is desirable during development.
	for i, option := range options {
		options[i].QuadletTemplateParsed = template.Must(template.New("quadlet").Parse(option.QuadletTemplate))
		options[i].PodmanTemplateParsed = template.Must(template.New("podman").Parse(option.PodmanTemplate))
	}

	return options
}

// Helper functions for image options
func optImageName() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Image",
		PodmanKey:       "image",
		Description:     "The image to pull. Use fully qualified image names for performance and robustness. Supports :tag or digests.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optImageTag() SchemaOption {
	return SchemaOption{
		QuadletKey:      "ImageTag",
		PodmanKey:       "tag",
		Description:     "The actual Fully Qualified Image Name (FQIN) when source is file/directory archive. Only meaningful for docker-archive sources.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "ImageTag={{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optAllTags() SchemaOption {
	return SchemaOption{
		QuadletKey:      "AllTags",
		PodmanKey:       "--all-tags",
		Description:     "Pull all tagged images in the repository. IMPORTANT: When using this, Podman doesn't iterate search registries but always uses docker.io.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--all-tags",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Pull all tags"},
		},
	}
}

func optPolicy() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Policy",
		PodmanKey:       "--policy",
		Description:     "Pull image policy. Default: always. Controls when images are pulled.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "always", Description: "Always pull the image"},
			{Value: "missing", Description: "Pull only if not in local storage"},
			{Value: "never", Description: "Never pull the image"},
			{Value: "newer", Description: "Pull if registry version is newer"},
		},
	}
}

func optArch() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Arch",
		PodmanKey:       "--arch",
		Description:     "Override the architecture. Default: host architecture. Example: arm.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "amd64", Description: "AMD64 architecture"},
			{Value: "arm64", Description: "ARM64 architecture"},
			{Value: "arm", Description: "ARM architecture"},
			{Value: "ppc64le", Description: "PowerPC64 LE architecture"},
			{Value: "s390x", Description: "IBM Z architecture"},
		},
	}
}

func optOS() SchemaOption {
	return SchemaOption{
		QuadletKey:      "OS",
		PodmanKey:       "--os",
		Description:     "Override the OS. Default: host OS. Example: windows.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "linux", Description: "Linux OS"},
			{Value: "windows", Description: "Windows OS"},
		},
	}
}

func optVariant() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Variant",
		PodmanKey:       "--variant",
		Description:     "Use architecture variant (e.g., arm/v5, arm/v7) for multi-variant ARM images.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "v6", Description: "ARM v6"},
			{Value: "v7", Description: "ARM v7"},
			{Value: "v8", Description: "ARM v8"},
		},
	}
}

func optAuthFile() SchemaOption {
	return SchemaOption{
		QuadletKey:      "AuthFile",
		PodmanKey:       "--authfile",
		Description:     "Path to authentication file. Default: ${XDG_RUNTIME_DIR}/containers/auth.json (Linux) or $HOME/.config/containers/auth.json (Windows/macOS). Created by 'podman login'.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optCertDir() SchemaOption {
	return SchemaOption{
		QuadletKey:      "CertDir",
		PodmanKey:       "--cert-dir",
		Description:     "Use certificates at path (*.crt, *.cert, *.key) to connect to registry. Default: /etc/containers/certs.d.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optCreds() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Creds",
		PodmanKey:       "--creds",
		Description:     "Credentials for registry. Format: [username[:password]]. Password entered without echo if not supplied.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optDecryptionKey() SchemaOption {
	return SchemaOption{
		QuadletKey:      "DecryptionKey",
		PodmanKey:       "--decryption-key",
		Description:     "Key for decryption of images. Format: [key[:passphrase]]. Decryption tried with all keys.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optImageRetry() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Retry",
		PodmanKey:       "--retry",
		Description:     "Number of times to retry pulling image in case of failure. Default: 3.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optImageRetryDelay() SchemaOption {
	return SchemaOption{
		QuadletKey:      "RetryDelay",
		PodmanKey:       "--retry-delay",
		Description:     "Duration of delay between retry attempts. Default: 2s with exponential backoff unless explicitly set.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optTLSVerify() SchemaOption {
	return SchemaOption{
		QuadletKey:      "TLSVerify",
		PodmanKey:       "--tls-verify",
		Description:     "Require HTTPS and verify certificates. Default: true. Can be overridden for insecure registries in containers-registries.conf.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Verify TLS certificates"},
			{Value: "false", Description: "Do not verify TLS certificates"},
		},
	}
}

func optPodmanArgsImage() SchemaOption {
	return SchemaOption{
		QuadletKey:      "PodmanArgs",
		PodmanKey:       "podman",
		Description:     "Arguments passed to end of 'podman image pull' command.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optGlobalArgsImage() SchemaOption {
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

func optContainersConfModuleImage() SchemaOption {
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

// optImageSchema generates the complete image schema
func GetImageSchema() Schema {
	options := GetImageOptions()
	PopulateValidators(options)

	return Schema{
		{
			Type:    "Image",
			Options: options,
		},
	}
}
