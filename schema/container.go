package schema

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"text/template"
)

// OptionValue represents a valid value for an option
type OptionValue struct {
	Value       string `json:"value"`
	Description string `json:"description"`
	Info        string `json:"info,omitempty"`
	Validator   string `json:"validator"`
}

// SchemaOption represents a single option in the schema
type SchemaOption struct {
	QuadletKey            string             `json:"quadlet-key"`
	PodmanKey             string             `json:"podman-key"`
	Description           string             `json:"description"`
	QuadletTemplate       string             `json:"quadlet-template"`
	PodmanTemplate        string             `json:"podman-template"`
	AllowMultiple         bool               `json:"allow-multiple"`
	Values                []OptionValue      `json:"values"`
	QuadletTemplateParsed *template.Template `json:"-"`
	PodmanTemplateParsed  *template.Template `json:"-"`
}

// SchemaType represents the schema for a unit type
type SchemaType struct {
	Type    string         `json:"type"`
	Options []SchemaOption `json:"options"`
}

// Schema represents the complete schema
type Schema []SchemaType

// OptionMetadata holds extracted metadata for an option
type OptionMetadata struct {
	QuadletKey     string
	QuadletFormat  string // Format string with placeholders
	PodmanKey      string
	PodmanFormat   string // Format string with placeholders
	Description    string
	AllowMultiple  bool
	KnownValues    []OptionValue
	ValidatorRegex string
	ValueType      string // e.g., "ipv4", "integer", "duration", "path", "capability"
}

// KnownValueSets contains predefined sets of valid values for specific option types
var KnownValueSets = map[string][]OptionValue{
	"capability": {
		{Value: "CAP_AUDIT_WRITE", Description: "Write to audit log", Validator: ""},
		{Value: "CAP_CHOWN", Description: "Change file ownership", Validator: ""},
		{Value: "CAP_DAC_OVERRIDE", Description: "Bypass file read, write, and execute permission checks", Validator: ""},
		{Value: "CAP_FOWNER", Description: "Bypass file read, write, execute, and delete permission checks", Validator: ""},
		{Value: "CAP_SETFCAP", Description: "Set file capabilities", Validator: ""},
		{Value: "CAP_SETGID", Description: "Change GID", Validator: ""},
		{Value: "CAP_SETUID", Description: "Change UID", Validator: ""},
		{Value: "CAP_SYS_ADMIN", Description: "Administer the system (perform system administration)", Validator: ""},
		{Value: "CAP_SYS_CHROOT", Description: "Change root directory", Validator: ""},
		{Value: "CAP_SYS_PTRACE", Description: "Trace processes", Validator: ""},
	},
	"pull_policy": {
		{Value: "always", Description: "Always pull the image and throw an error if the pull fails", Validator: ""},
		{Value: "missing", Description: "Pull the image only when the image is not in the local containers storage", Validator: ""},
		{Value: "never", Description: "Never pull the image but use the one from the local containers storage", Validator: ""},
		{Value: "newer", Description: "Pull if the image on the registry is newer than the one in the local containers storage", Validator: ""},
	},
	"auto_update": {
		{Value: "registry", Description: "Requires a fully-qualified image reference to be used to create the container", Validator: ""},
		{Value: "local", Description: "Compare the image a container is using to the image with its raw name in local storage", Validator: ""},
	},
	"cgroups_mode": {
		{Value: "enabled", Description: "Creates a new cgroup under the cgroup-parent", Validator: ""},
		{Value: "disabled", Description: "Forces the container to not create cgroups", Validator: ""},
		{Value: "no-conmon", Description: "Disables a new cgroup only for the conmon process", Validator: ""},
		{Value: "split", Description: "Splits the current cgroup in two sub-cgroups (default)", Validator: ""},
	},
	"log_driver": {
		{Value: "k8s-file", Description: "Kubernetes-style file logging", Validator: ""},
		{Value: "journald", Description: "Write logs to journald", Validator: ""},
		{Value: "none", Description: "No logging", Validator: ""},
		{Value: "passthrough", Description: "Pass logs directly to stdout/stderr", Validator: ""},
		{Value: "passthrough-tty", Description: "Pass logs to TTY if available", Validator: ""},
	},
	"health_on_failure": {
		{Value: "none", Description: "Take no action", Validator: ""},
		{Value: "kill", Description: "Kill the container", Validator: ""},
		{Value: "restart", Description: "Restart the container", Validator: ""},
		{Value: "stop", Description: "Stop the container", Validator: ""},
	},
	"notify_mode": {
		{Value: "true", Description: "Enable systemd startup notify", Validator: ""},
		{Value: "healthy", Description: "Postpone notification until container is healthy", Validator: ""},
	},
	"user_ns_mode": {
		{Value: "auto", Description: "Automatically create a unique user namespace", Validator: ""},
		{Value: "host", Description: "Use the host's user namespace (default)", Validator: ""},
		{Value: "keep-id", Description: "Map current user's UID:GID to same values in container", Validator: ""},
		{Value: "nomap", Description: "Do not map current user's UID:GID into the container", Validator: ""},
	},
	"signal": {
		{Value: "SIGTERM", Description: "Termination signal (default)", Validator: ""},
		{Value: "SIGKILL", Description: "Kill signal", Validator: ""},
		{Value: "SIGINT", Description: "Interrupt signal", Validator: ""},
		{Value: "SIGHUP", Description: "Hangup signal", Validator: ""},
		{Value: "SIGQUIT", Description: "Quit signal", Validator: ""},
		{Value: "SIGABRT", Description: "Abort signal", Validator: ""},
		{Value: "SIGALRM", Description: "Alarm signal", Validator: ""},
		{Value: "SIGUSR1", Description: "User-defined signal 1", Validator: ""},
		{Value: "SIGUSR2", Description: "User-defined signal 2", Validator: ""},
		{Value: "SIGCHLD", Description: "Child process signal", Validator: ""},
		{Value: "SIGCONT", Description: "Continue signal", Validator: ""},
		{Value: "SIGSTOP", Description: "Stop signal", Validator: ""},
	},
}

// ValidatorPatterns contains regex patterns for common value types
var ValidatorPatterns = map[string]string{
	"ipv4":             `^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`,
	"ipv6":             `^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$`,
	"integer":          `^-?[0-9]+$`,
	"positive_integer": `^[0-9]+$`,
	"signal":           `^(SIGTERM|SIGKILL|SIGINT|SIGHUP|SIGQUIT|SIGABRT|SIGALRM|SIGUSR1|SIGUSR2|SIGCHLD|SIGCONT|SIGSTOP)$`,
	"duration":         `^([0-9]+(s|m|h))+$`,
	"path":             `^/[a-zA-Z0-9_\-./]*$`,
	"hostname":         `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`,
	"memory_unit":      `^[0-9]+(b|k|m|g|B|K|M|G)$`,
}

// GenerateContainerOptions generates all container schema options
func GetContainerOptions() []SchemaOption {
	options := []SchemaOption{
		// Image and naming
		optContainerImage(),
		optContainerName(),
		optPull(),

		// Capabilities and security
		optAddCapability(),
		optDropCapability(),
		optAddDevice(),
		optSeccompProfile(),
		optSecurityLabelDisable(),
		optSecurityLabelType(),
		optSecurityLabelLevel(),
		optSecurityLabelFileType(),
		optSecurityLabelNested(),

		// Networking
		optNetwork(),
		optPublishPort(),
		optIP(),
		optIP6(),
		optDNS(),
		optDNSOption(),
		optDNSSearch(),
		optAddHost(),
		optNetworkAlias(),
		optHostName(),

		// Environment and resources
		optEnvironment(),
		optEnvironmentFile(),
		optEnvironmentHost(),
		optMemory(),
		optShmSize(),
		optCgroupsMode(),

		// User and groups
		optUser(),
		optGroup(),
		optGroupAdd(),
		optUIDMap(),
		optGIDMap(),
		optSubUIDMap(),
		optSubGIDMap(),
		optUserNS(),

		// Storage and volumes
		optVolume(),
		optMount(),
		optRootfs(),
		optReadOnly(),
		optReadOnlyTmpfs(),
		optTmpfs(),
		optMask(),
		optUnmask(),

		// Health and startup
		optHealthCmd(),
		optHealthInterval(),
		optHealthTimeout(),
		optHealthRetries(),
		optHealthStartPeriod(),
		optHealthStartupCmd(),
		optHealthStartupInterval(),
		optHealthStartupTimeout(),
		optHealthStartupRetries(),
		optHealthStartupSuccess(),
		optHealthOnFailure(),
		optHealthMaxLogSize(),
		optHealthMaxLogCount(),
		optHealthLogDestination(),

		// Metadata
		optLabel(),
		optAnnotation(),

		// Container execution
		optEntrypoint(),
		optExec(),
		optStopSignal(),
		optStopTimeout(),
		optWorkingDir(),
		optRunInit(),

		// Restart and notifications
		optNotify(),
		optAutoUpdate(),

		// Logging
		optLogDriver(),
		optLogOpt(),

		// Advanced options
		optNoNewPrivileges(),
		optPrivileged(),
		optPodOption(),
		optStartWithPod(),
		optExposeHostPort(),
		optHttpProxy(),
		optRetry(),
		optRetryDelay(),
		optReloadCmd(),
		optReloadSignal(),
		optSysctl(),
		optTimezone(),
		optUlimit(),
		optContainersConfModule(),
		optGlobalArgs(),
		optPodmanArgs(),
		optSecret(),
	}

	// Pre-parse templates for all options to catch errors early. Will panic if any template is invalid, which is desirable during development.
	for i, option := range options {
		options[i].QuadletTemplateParsed = template.Must(template.New("quadlet").Parse(option.QuadletTemplate))
		options[i].PodmanTemplateParsed = template.Must(template.New("podman").Parse(option.PodmanTemplate))
	}

	return options
}

// Helper functions for container options
func optContainerImage() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Image",
		PodmanKey:       "image",
		Description:     "The image to run in the container. Use fully qualified image names (e.g., quay.io/podman/stable:latest) for performance and robustness.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optContainerName() SchemaOption {
	return SchemaOption{
		QuadletKey:      "ContainerName",
		PodmanKey:       "--name",
		Description:     "Assign a name to the container. Default is systemd-<unitname>. The name can be useful as a more human-friendly way to identify containers.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optPull() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Pull",
		PodmanKey:       "--pull",
		Description:     "Pull image policy. Controls when images are pulled from registries.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          KnownValueSets["pull_policy"],
	}
}

func optDropCapability() SchemaOption {
	return SchemaOption{
		QuadletKey:      "DropCapability",
		PodmanKey:       "--cap-drop",
		Description:     "Drop Linux capabilities from the default set, or 'all' to drop all capabilities. This is a space-separated list.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          KnownValueSets["capability"],
	}
}

func optAddDevice() SchemaOption {
	return SchemaOption{
		QuadletKey:      "AddDevice",
		PodmanKey:       "--device",
		Description:     "Add a host device to the container. Format: HOST-DEVICE[:CONTAINER-DEVICE[:PERMISSIONS]]. Example: /dev/sdc:/dev/xvdc:rwm",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optSeccompProfile() SchemaOption {
	return SchemaOption{
		QuadletKey:      "SeccompProfile",
		PodmanKey:       "--security-opt seccomp=",
		Description:     "Set the seccomp profile. Can be a JSON file path or 'unconfined' to disable seccomp filtering.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--security-opt seccomp={{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "unconfined", Description: "Disable seccomp filtering"},
		},
	}
}

func optSecurityLabelDisable() SchemaOption {
	return SchemaOption{
		QuadletKey:      "SecurityLabelDisable",
		PodmanKey:       "--security-opt label=disable",
		Description:     "Turn off label separation for the container (SELinux).",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--security-opt label=disable",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Disable SELinux labels"},
			{Value: "false", Description: "Enable SELinux labels"},
		},
	}
}

func optSecurityLabelType() SchemaOption {
	return SchemaOption{
		QuadletKey:      "SecurityLabelType",
		PodmanKey:       "--security-opt label=type:",
		Description:     "Set the SELinux label process type.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--security-opt label=type:{{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optSecurityLabelLevel() SchemaOption {
	return SchemaOption{
		QuadletKey:      "SecurityLabelLevel",
		PodmanKey:       "--security-opt label=level:",
		Description:     "Set the SELinux label process level (e.g., s0:c1,c2).",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--security-opt label=level:{{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optSecurityLabelFileType() SchemaOption {
	return SchemaOption{
		QuadletKey:      "SecurityLabelFileType",
		PodmanKey:       "--security-opt label=filetype:",
		Description:     "Set the SELinux label file type for the container files.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--security-opt label=filetype:{{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optSecurityLabelNested() SchemaOption {
	return SchemaOption{
		QuadletKey:      "SecurityLabelNested",
		PodmanKey:       "--security-opt label=nested",
		Description:     "Allow SELinux labels to function within the container for nested container separation.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--security-opt label=nested",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Enable nested labels"},
			{Value: "false", Description: "Disable nested labels"},
		},
	}
}

func optPublishPort() SchemaOption {
	return SchemaOption{
		QuadletKey:      "PublishPort",
		PodmanKey:       "--publish",
		Description:     "Publish a container port to the host. Format: [[ip:][hostPort]:]containerPort[/protocol]. Protocol defaults to tcp. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values: []OptionValue{
			{Value: "tcp", Description: "Publish TCP port (default)"},
			{Value: "udp", Description: "Publish UDP port"},
			{Value: "sctp", Description: "Publish SCTP port (rootful containers only)"},
		},
	}
}

func optDNSOption() SchemaOption {
	return SchemaOption{
		QuadletKey:      "DNSOption",
		PodmanKey:       "--dns-option",
		Description:     "Set custom DNS options. Can be specified multiple times. Invalid with Network=none or Network=container:id.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optDNSSearch() SchemaOption {
	return SchemaOption{
		QuadletKey:      "DNSSearch",
		PodmanKey:       "--dns-search",
		Description:     "Set custom DNS search domains. Use DNSSearch=. to remove search domain. Invalid with Network=none or Network=container:id.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optAddHost() SchemaOption {
	return SchemaOption{
		QuadletKey:      "AddHost",
		PodmanKey:       "--add-host",
		Description:     "Add a custom host-to-IP mapping. Format: hostname[;hostname[;...]:ip. Can also use 'host-gateway' for host IP resolution.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optNetworkAlias() SchemaOption {
	return SchemaOption{
		QuadletKey:      "NetworkAlias",
		PodmanKey:       "--network-alias",
		Description:     "Add a network-scoped alias for the container across all networks joined.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optHostName() SchemaOption {
	return SchemaOption{
		QuadletKey:      "HostName",
		PodmanKey:       "--hostname",
		Description:     "Set the container's hostname. Only works with private UTS namespace (default). Added to /etc/hosts with container's primary IP.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optEnvironmentFile() SchemaOption {
	return SchemaOption{
		QuadletKey:      "EnvironmentFile",
		PodmanKey:       "--env-file",
		Description:     "Read environment variables from a line-delimited file.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optEnvironmentHost() SchemaOption {
	return SchemaOption{
		QuadletKey:      "EnvironmentHost",
		PodmanKey:       "--env-host",
		Description:     "Use host environment inside the container. Not available with remote Podman client.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--env-host",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Use host environment"},
		},
	}
}

func optShmSize() SchemaOption {
	return SchemaOption{
		QuadletKey:      "ShmSize",
		PodmanKey:       "--shm-size",
		Description:     "Size of /dev/shm. Units: b (bytes), k (kibibytes), m (mebibytes), g (gibibytes). Default: 64m. When 0, no limit.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optCgroupsMode() SchemaOption {
	return SchemaOption{
		QuadletKey:      "CgroupsMode",
		PodmanKey:       "--cgroups",
		Description:     "Determines whether the container creates cgroups. Default for Quadlet is 'split' (different from CLI default 'enabled').",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          KnownValueSets["cgroups_mode"],
	}
}

func optUser() SchemaOption {
	return SchemaOption{
		QuadletKey:      "User",
		PodmanKey:       "--user",
		Description:     "Sets the username or UID and optionally groupname or GID. Format: user[:group] or UID[:GID].",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optGroup() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Group",
		PodmanKey:       "--user",
		Description:     "The numeric GID to run as inside the container (part of --user UID:GID).",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--user :{{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optGroupAdd() SchemaOption {
	return SchemaOption{
		QuadletKey:      "GroupAdd",
		PodmanKey:       "--group-add",
		Description:     "Assign additional groups to the primary user. Use 'keep-groups' to keep supplementary group access.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values: []OptionValue{
			{Value: "keep-groups", Description: "Keep supplementary group access"},
		},
	}
}

func optUIDMap() SchemaOption {
	return SchemaOption{
		QuadletKey:      "UIDMap",
		PodmanKey:       "--uidmap",
		Description:     "Run in a new user namespace with UID mapping. Format: [flags]container_uid:from_uid[:amount]. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optGIDMap() SchemaOption {
	return SchemaOption{
		QuadletKey:      "GIDMap",
		PodmanKey:       "--gidmap",
		Description:     "Run in a new user namespace with GID mapping. Format: [flags]container_gid:from_gid[:amount]. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optSubUIDMap() SchemaOption {
	return SchemaOption{
		QuadletKey:      "SubUIDMap",
		PodmanKey:       "--subuidname",
		Description:     "Run in a new user namespace using the map with name in /etc/subuid. Conflicts with UserNS= and UIDMap=.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optSubGIDMap() SchemaOption {
	return SchemaOption{
		QuadletKey:      "SubGIDMap",
		PodmanKey:       "--subgidname",
		Description:     "Run in a new user namespace using the map with name in /etc/subgid. Conflicts with UserNS= and GIDMap=.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optUserNS() SchemaOption {
	return SchemaOption{
		QuadletKey:      "UserNS",
		PodmanKey:       "--userns",
		Description:     "Set the user namespace mode. Incompatible with GIDMap=, UIDMap=, SubUIDMap=, and SubGIDMap=.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          KnownValueSets["user_ns_mode"],
	}
}

func optMount() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Mount",
		PodmanKey:       "--mount",
		Description:     "Attach a filesystem mount to the container. Format: type=TYPE,TYPE-SPECIFIC-OPTION[,...]. Supports: artifact, bind, devpts, glob, image, ramfs, tmpfs, volume.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values: []OptionValue{
			{Value: "bind", Description: "Bind mount from host"},
			{Value: "volume", Description: "Named volume mount"},
			{Value: "tmpfs", Description: "Temporary filesystem"},
			{Value: "image", Description: "Mount from container image"},
			{Value: "devpts", Description: "Device pseudo-terminal"},
			{Value: "ramfs", Description: "RAM filesystem"},
		},
	}
}

func optRootfs() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Rootfs",
		PodmanKey:       "--rootfs",
		Description:     "Use an exploded container on the filesystem as the root. Conflicts with Image=. Useful for running containers without image management.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optReadOnly() SchemaOption {
	return SchemaOption{
		QuadletKey:      "ReadOnly",
		PodmanKey:       "--read-only",
		Description:     "Mount the container's root filesystem as read-only.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--read-only",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Mount root as read-only"},
		},
	}
}

func optReadOnlyTmpfs() SchemaOption {
	return SchemaOption{
		QuadletKey:      "ReadOnlyTmpfs",
		PodmanKey:       "--read-only-tmpfs",
		Description:     "When using --read-only, mount read-write tmpfs on /dev, /dev/shm, /run, /tmp, and /var/tmp. Default: true.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--read-only-tmpfs",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Mount tmpfs for read-only root"},
			{Value: "false", Description: "Do not mount tmpfs"},
		},
	}
}

func optTmpfs() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Tmpfs",
		PodmanKey:       "--tmpfs",
		Description:     "Create a tmpfs mount. Example: /work:rw,size=787448k,mode=1777. Supports mount options: rw,noexec,nosuid,nodev.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optMask() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Mask",
		PodmanKey:       "--security-opt mask=",
		Description:     "Specify paths to mask separated by colon. Masked paths cannot be accessed inside the container.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--security-opt mask={{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optUnmask() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Unmask",
		PodmanKey:       "--security-opt unmask=",
		Description:     "Specify paths to unmask. Use 'ALL' to unmask all masked paths. Default masked paths: /proc/acpi, /proc/kcore, /proc/keys, /proc/latency_stats, /proc/sched_debug, /proc/scsi, /proc/timer_list, /proc/timer_stats, /sys/firmware, /sys/fs/selinux.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--security-opt unmask={{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "ALL", Description: "Unmask all default masked paths"},
		},
	}
}

func optHealthCmd() SchemaOption {
	return SchemaOption{
		QuadletKey:      "HealthCmd",
		PodmanKey:       "--health-cmd",
		Description:     "Set or alter a healthcheck command. Use 'none' to disable. Multiple options in JSON array form.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optHealthInterval() SchemaOption {
	return SchemaOption{
		QuadletKey:      "HealthInterval",
		PodmanKey:       "--health-interval",
		Description:     "Set interval for healthchecks. Use 'disable' for no timer. Default: 30s.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optHealthTimeout() SchemaOption {
	return SchemaOption{
		QuadletKey:      "HealthTimeout",
		PodmanKey:       "--health-timeout",
		Description:     "Maximum time for healthcheck command to complete. Format: 1m22s. Default: 30s. Command gets SIGKILL if timeout exceeded.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optHealthRetries() SchemaOption {
	return SchemaOption{
		QuadletKey:      "HealthRetries",
		PodmanKey:       "--health-retries",
		Description:     "Number of retries before healthcheck is unhealthy. Default: 3.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optHealthStartPeriod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "HealthStartPeriod",
		PodmanKey:       "--health-start-period",
		Description:     "Initialization time for container bootstrap. Format: 2m3s. Default: 0s. Health stays 'starting' until this period or first success.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optHealthStartupCmd() SchemaOption {
	return SchemaOption{
		QuadletKey:      "HealthStartupCmd",
		PodmanKey:       "--health-startup-cmd",
		Description:     "Startup healthcheck command to run until successful.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optHealthStartupInterval() SchemaOption {
	return SchemaOption{
		QuadletKey:      "HealthStartupInterval",
		PodmanKey:       "--health-startup-interval",
		Description:     "Interval between startup healthcheck attempts. Default: 5s.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optHealthStartupTimeout() SchemaOption {
	return SchemaOption{
		QuadletKey:      "HealthStartupTimeout",
		PodmanKey:       "--health-startup-timeout",
		Description:     "Maximum time for startup healthcheck to complete. Default: 30s.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optHealthStartupRetries() SchemaOption {
	return SchemaOption{
		QuadletKey:      "HealthStartupRetries",
		PodmanKey:       "--health-startup-retries",
		Description:     "Number of startup healthcheck failures to tolerate before failure. Default: 0 (any success starts regular checks).",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optHealthStartupSuccess() SchemaOption {
	return SchemaOption{
		QuadletKey:      "HealthStartupSuccess",
		PodmanKey:       "--health-startup-success",
		Description:     "Number of successful startup healthcheck runs before regular health checks begin. Default: 0.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optHealthOnFailure() SchemaOption {
	return SchemaOption{
		QuadletKey:      "HealthOnFailure",
		PodmanKey:       "--health-on-failure",
		Description:     "Action to take when container becomes unhealthy. Default: none.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          KnownValueSets["health_on_failure"],
	}
}

func optHealthMaxLogSize() SchemaOption {
	return SchemaOption{
		QuadletKey:      "HealthMaxLogSize",
		PodmanKey:       "--health-max-log-size",
		Description:     "Maximum length in characters of stored healthcheck log. Default: 500 characters. 0 means unlimited.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optHealthMaxLogCount() SchemaOption {
	return SchemaOption{
		QuadletKey:      "HealthMaxLogCount",
		PodmanKey:       "--health-max-log-count",
		Description:     "Maximum number of attempts in healthcheck log file. Default: 5 attempts. 0 means unlimited.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optHealthLogDestination() SchemaOption {
	return SchemaOption{
		QuadletKey:      "HealthLogDestination",
		PodmanKey:       "--health-log-destination",
		Description:     "Destination for healthcheck logs: 'local' (default, overlay), 'directory' (custom path), or 'events_logger'.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "local", Description: "Store in overlay containers (default)"},
			{Value: "events_logger", Description: "Write with logging mechanism set by events_logger"},
		},
	}
}

func optAnnotation() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Annotation",
		PodmanKey:       "--annotation",
		Description:     "Add an annotation to the container. Format: key=value. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optEntrypoint() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Entrypoint",
		PodmanKey:       "--entrypoint",
		Description:     "Override the default ENTRYPOINT from the image. Specify multi-option commands as JSON string.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optExec() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Exec",
		PodmanKey:       "command",
		Description:     "Command to execute in the container (appears after image name in ExecStart).",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optStopSignal() SchemaOption {
	return SchemaOption{
		QuadletKey:      "StopSignal",
		PodmanKey:       "--stop-signal",
		Description:     "Signal to send to stop the container. Valid signals: SIGTERM, SIGKILL, SIGINT, SIGHUP, SIGQUIT, SIGABRT, SIGALRM, SIGUSR1, SIGUSR2, SIGCHLD, SIGCONT, SIGSTOP.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          KnownValueSets["signal"],
	}
}

func optStopTimeout() SchemaOption {
	return SchemaOption{
		QuadletKey:      "StopTimeout",
		PodmanKey:       "--stop-timeout",
		Description:     "Timeout in seconds for stop operation before killing.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optWorkingDir() SchemaOption {
	return SchemaOption{
		QuadletKey:      "WorkingDir",
		PodmanKey:       "--workdir",
		Description:     "Working directory inside the container. Default: root (/).",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optRunInit() SchemaOption {
	return SchemaOption{
		QuadletKey:      "RunInit",
		PodmanKey:       "--init",
		Description:     "Run an init inside the container that forwards signals and reaps processes.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--init",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Enable init"},
		},
	}
}

func optNotify() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Notify",
		PodmanKey:       "--sdnotify",
		Description:     "Enable systemd startup notification. Set to 'healthy' to postpone notification until container is healthy.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--sdnotify {{.Value}}",
		AllowMultiple:   false,
		Values:          KnownValueSets["notify_mode"],
	}
}

func optAutoUpdate() SchemaOption {
	return SchemaOption{
		QuadletKey:      "AutoUpdate",
		PodmanKey:       "label",
		Description:     "Indicates whether the container will be auto-updated. 'registry' requires fully-qualified image. 'local' compares local image.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--label io.containers.autoupdate={{.Value}}",
		AllowMultiple:   false,
		Values:          KnownValueSets["auto_update"],
	}
}

func optLogDriver() SchemaOption {
	return SchemaOption{
		QuadletKey:      "LogDriver",
		PodmanKey:       "--log-driver",
		Description:     "Logging driver. Options: k8s-file, journald (default), none, passthrough, passthrough-tty. json-file aliased to k8s-file for compatibility.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          KnownValueSets["log_driver"],
	}
}

func optLogOpt() SchemaOption {
	return SchemaOption{
		QuadletKey:      "LogOpt",
		PodmanKey:       "--log-opt",
		Description:     "Logging driver specific options. Supports: path=/var/log/container.json, max-size=10mb, tag=custom_tag, label=CONTAINER_IMAGE={{.ImageName}}.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optNoNewPrivileges() SchemaOption {
	return SchemaOption{
		QuadletKey:      "NoNewPrivileges",
		PodmanKey:       "--security-opt no-new-privileges",
		Description:     "Disable container processes from gaining additional privileges via setuid and file capabilities. Default: false.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--security-opt no-new-privileges",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Disable new privileges"},
			{Value: "false", Description: "Allow new privileges"},
		},
	}
}

func optPrivileged() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Privileged",
		PodmanKey:       "--privileged",
		Description:     "Run the container in privileged mode. Gives full capabilities to the container.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--privileged",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Enable privileged mode"},
		},
	}
}

func optPodOption() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Pod",
		PodmanKey:       "--pod",
		Description:     "Link container to a Quadlet .pod unit. Value must be <name>.pod format. The .pod unit must exist.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optStartWithPod() SchemaOption {
	return SchemaOption{
		QuadletKey:      "StartWithPod",
		PodmanKey:       "service",
		Description:     "If Pod= is defined, start the container by the pod. Default: true.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "StartWithPod={{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Start with pod"},
		},
	}
}

func optExposeHostPort() SchemaOption {
	return SchemaOption{
		QuadletKey:      "ExposeHostPort",
		PodmanKey:       "--expose",
		Description:     "Expose a port or range of ports (e.g., 3300-3310). Matches image EXPOSE instruction but has no effect unless -P/--publish-all is used.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optHttpProxy() SchemaOption {
	return SchemaOption{
		QuadletKey:      "HttpProxy",
		PodmanKey:       "--http-proxy",
		Description:     "Pass proxy environment variables to container. Default: true. Set to false if host needs proxy but container doesn't.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "--http-proxy={{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{Value: "true", Description: "Pass proxy variables"},
			{Value: "false", Description: "Do not pass proxy variables"},
		},
	}
}

func optRetry() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Retry",
		PodmanKey:       "--retry",
		Description:     "Number of times to retry pulling image in case of failure. Default: 3.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optRetryDelay() SchemaOption {
	return SchemaOption{
		QuadletKey:      "RetryDelay",
		PodmanKey:       "--retry-delay",
		Description:     "Duration of delay between retry attempts when pulling images. Default: starts at 2s and exponentially backs off unless set.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optReloadCmd() SchemaOption {
	return SchemaOption{
		QuadletKey:      "ReloadCmd",
		PodmanKey:       "ExecReload",
		Description:     "Command to reload the container configuration without restarting. Adds ExecReload to the service.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "/usr/bin/podman exec {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optReloadSignal() SchemaOption {
	return SchemaOption{
		QuadletKey:      "ReloadSignal",
		PodmanKey:       "ExecReload",
		Description:     "Signal to send for reload instead of command. Adds ExecReload using kill with the signal.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "/usr/bin/podman kill --signal {{.Value}}",
		AllowMultiple:   false,
		Values:          KnownValueSets["signal"],
	}
}

func optSysctl() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Sysctl",
		PodmanKey:       "--sysctl",
		Description:     "Configure namespaced kernel parameters. Format: name=value. For IPC: kernel.msgmax, kernel.shm*, etc. For network: net.* options.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optTimezone() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Timezone",
		PodmanKey:       "--tz",
		Description:     "Set timezone in container. Use area-based timezones, GMT time, or 'local' to match host.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
	}
}

func optUlimit() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Ulimit",
		PodmanKey:       "--ulimit",
		Description:     "Set ulimit values. Format: name=soft[:hard]. Use -1 for unlimited. Special value 'host' copies host config.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optContainersConfModule() SchemaOption {
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

func optGlobalArgs() SchemaOption {
	return SchemaOption{
		QuadletKey:      "GlobalArgs",
		PodmanKey:       "podman",
		Description:     "Arguments passed directly after 'podman' in generated file. Can be used for unsupported features. Not recommended.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optPodmanArgs() SchemaOption {
	return SchemaOption{
		QuadletKey:      "PodmanArgs",
		PodmanKey:       "podman",
		Description:     "Arguments passed to end of 'podman' command. Can be used for unsupported features. Not recommended.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
	}
}

func optSecret() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Secret",
		PodmanKey:       "--secret",
		Description:     "Give container access to a secret. Format: secret[,opt=opt ...]. Options: type=mount|env, target=target, uid=0, gid=0, mode=0. Can be specified multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}}={{.Value}}",
		AllowMultiple:   true,
		Values: []OptionValue{
			{Value: "type=mount", Description: "Mount secret as file (default)"},
			{Value: "type=env", Description: "Expose secret as environment variable"},
		},
	}
}

func optAddCapability() SchemaOption {
	return SchemaOption{
		QuadletKey:      "AddCapability",
		PodmanKey:       "--cap-add",
		Description:     "Add Linux capabilities to the container. Multiple capabilities can be added by specifying this option multiple times.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          KnownValueSets["capability"],
	}
}

func optIP() SchemaOption {
	return SchemaOption{
		QuadletKey:      "IP",
		PodmanKey:       "--ip",
		Description:     "Specify a static IPv4 address for the container. Must be within the network's IP address pool (default 10.88.0.0/16).",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
		// Note: validator will be populated at runtime
	}
}

func optIP6() SchemaOption {
	return SchemaOption{
		QuadletKey:      "IP6",
		PodmanKey:       "--ip6",
		Description:     "Specify a static IPv6 address for the container. Must be within the network's IPv6 address pool (default fd00:dead:beef::/48). This option can only be used if the container is joined to only a single network. To specify multiple static IPv6 addresses per container, set multiple networks using the Network= option with a static IPv6 address specified for each using the ip6 mode for that option.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
		// Note: validator will be populated at runtime
	}
}

func optDNS() SchemaOption {
	return SchemaOption{
		QuadletKey:      "DNS",
		PodmanKey:       "--dns",
		Description:     "Set custom DNS servers for the container. Can be specified multiple times to add multiple DNS servers. Use 'none' to disable /etc/resolv.conf creation.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
		// Note: validator will be populated at runtime for IP addresses or special value 'none'
	}
}

func optEnvironment() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Environment",
		PodmanKey:       "--env",
		Description:     "Set environment variables in the container. Format: key=value. Can be specified multiple times. If value is omitted, uses value from host environment if set.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values:          []OptionValue{},
		// Note: value is freeform key=value pairs
	}
}

func optMemory() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Memory",
		PodmanKey:       "--memory",
		Description:     "Memory limit for the container. A unit can be b (bytes), k (kibibytes), m (mebibytes), or g (gibibytes). A limit of 0 means no limit.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values:          []OptionValue{},
		// Note: validator will be populated at runtime
	}
}

func optLabel() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Label",
		PodmanKey:       "--label",
		Description:     "Add metadata to the container. Format: key=value. Can be specified multiple times to add multiple labels.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values: []OptionValue{{
			Value:       "",
			Description: "Space-separated freeform key=value pairs (e.g. Label=key=value key2=value2).",
			Info:        "",
			Validator:   "",
		},
		},
		// Note: value is freeform key=value pairs
	}
}

func optVolume() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Volume",
		PodmanKey:       "--volume",
		Description:     "Create a bind mount or named volume. Format: [[SOURCE-VOLUME|HOST-DIR:]CONTAINER-DIR[:OPTIONS]]. Can be specified multiple times for multiple mounts. Supports bind, volume, tmpfs, and other mount types.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   true,
		Values: []OptionValue{
			{
				Value:       "bind",
				Description: "Bind mount - mounts a directory or file from the host into the container",
				Info:        "Use with paths like /host/path:/container/path:ro or /host/path:/container/path:rw",
				Validator:   "",
			},
			{
				Value:       "volume",
				Description: "Named volume mount - mounts a Podman named volume into the container",
				Info:        "Use with volume names like my_volume:/container/path",
				Validator:   "",
			},
			{
				Value:       "tmpfs",
				Description: "Temporary filesystem mount - creates an in-memory filesystem",
				Info:        "Use tmpfs:/container/path to create temporary storage",
				Validator:   "",
			},
		},
	}
}

func optNetwork() SchemaOption {
	return SchemaOption{
		QuadletKey:      "Network",
		PodmanKey:       "--network",
		Description:     "Set the network mode for the container. Supports bridge (default), host, container, pasta, and custom networks. Special case: if name ends with .network, a Podman network called systemd-$name is used.",
		QuadletTemplate: "{{.Key}}={{.Value}}",
		PodmanTemplate:  "{{.Key}} {{.Value}}",
		AllowMultiple:   false,
		Values: []OptionValue{
			{
				Value:       "bridge",
				Description: "Create a network stack on the default bridge (default for rootful containers)",
				Info:        "Supports options: alias=name, ip=IPv4, ip6=IPv6, mac=MAC, interface_name=name",
				Validator:   "",
			},
			{
				Value:       "host",
				Description: "Use the host's network namespace for the container",
				Info:        "Warning: gives container full access to abstract Unix domain sockets and TCP/UDP sockets bound to localhost",
				Validator:   "",
			},
			{
				Value:       "none",
				Description: "Create a network namespace but do not configure network interfaces",
				Info:        "Results in no network connectivity for the container",
				Validator:   "",
			},
			{
				Value:       "container:id",
				Description: "Reuse another container's network stack",
				Info:        "Use container:name_or_id to join specific container's network",
				Validator:   "",
			},
			{
				Value:       "pasta",
				Description: "Use pasta for user-mode networking (default for rootless containers)",
				Info:        "Supports pasta-specific options in the format: pasta:option1,option2",
				Validator:   "",
			},
		},
	}
}

// PopulateValidators adds regex validators to options that need them
func PopulateValidators(options []SchemaOption) {
	for i := range options {
		switch options[i].QuadletKey {
		case "IP":
			options[i].Values = []OptionValue{
				{
					Value:       "",
					Description: "IPv4 address",
					Info:        "Must be within network IP address pool",
					Validator:   ValidatorPatterns["ipv4"],
				},
			}
		case "DNS":
			options[i].Values = []OptionValue{
				{
					Value:       "none",
					Description: "Disable /etc/resolv.conf creation",
					Info:        "Image's /etc/resolv.conf will be used unchanged",
					Validator:   "",
				},
				{
					Value:       "",
					Description: "IPv4 or IPv6 address",
					Info:        "IP address for DNS server",
					Validator:   "^(" + ValidatorPatterns["ipv4"] + "|" + ValidatorPatterns["ipv6"] + "|none)$",
				},
			}
		case "Memory":
			options[i].Values = []OptionValue{
				{
					Value:       "",
					Description: "Memory with optional unit",
					Info:        "Units: b (bytes), k (kibibytes), m (mebibytes), g (gibibytes)",
					Validator:   `^([0-9]+|0)([bkmg])?$`,
				},
			}
		}
	}
}

// optSchema generates the complete container schema
func GenerateSchema() Schema {
	options := GetContainerOptions()
	PopulateValidators(options)

	return Schema{
		{
			Type:    "Container",
			Options: options,
		},
	}
}

// ValidateSchema performs basic validation on the generated schema
func ValidateSchema(schema Schema) error {
	for _, schemaType := range schema {
		for _, opt := range schemaType.Options {
			if opt.QuadletKey == "" {
				return fmt.Errorf("option missing quadlet-key")
			}
			if opt.PodmanKey == "" {
				return fmt.Errorf("option %s missing podman-key", opt.QuadletKey)
			}
			if opt.Description == "" {
				return fmt.Errorf("option %s missing description", opt.QuadletKey)
			}
			if opt.QuadletTemplate == "" {
				return fmt.Errorf("option %s missing quadlet-template", opt.QuadletKey)
			}
			if opt.PodmanTemplate == "" {
				return fmt.Errorf("option %s missing podman-template", opt.QuadletKey)
			}

			// Validate templates are valid Go templates
			_, err := NewTemplateValidator(opt.QuadletTemplate)
			if err != nil {
				return fmt.Errorf("option %s has invalid quadlet-template: %w", opt.QuadletKey, err)
			}
			_, err = NewTemplateValidator(opt.PodmanTemplate)
			if err != nil {
				return fmt.Errorf("option %s has invalid podman-template: %w", opt.QuadletKey, err)
			}

			// Validate regex patterns
			for _, val := range opt.Values {
				if val.Validator != "" {
					_, err := regexp.Compile(val.Validator)
					if err != nil {
						return fmt.Errorf("option %s value %s has invalid validator regex: %w", opt.QuadletKey, val.Value, err)
					}
				}
			}
		}
	}
	return nil
}

// ExportJSON exports the schema to JSON
func ExportJSON(schema Schema) (string, error) {
	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// NewTemplateValidator validates a template string
func NewTemplateValidator(templateStr string) (interface{}, error) {
	// Simple validation - check that template has expected structure
	if !strings.Contains(templateStr, "{{") {
		return nil, fmt.Errorf("template missing template variables")
	}
	if !strings.Contains(templateStr, "}}") {
		return nil, fmt.Errorf("template has unmatched braces")
	}
	return nil, nil
}
