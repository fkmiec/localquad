package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"html/template"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	. "github.com/fkmiec/quadctl/schema"
	"github.com/jedib0t/go-pretty/v6/list"
	"github.com/jedib0t/go-pretty/v6/table"
)

// Consts and Config
const (
	ToolName = "quadctl"
)

var (
	extensions = map[string]bool{
		".container": true,
		".pod":       true,
		".network":   true,
		".volume":    true,
		".kube":      true,
	}
	// Regex to extract images from YAML (KubernetesYAML=) - Simple and brittle
	yamlImageRegex = regexp.MustCompile(`image:\s*["']?([^"'\s]+)["']?`)

	quadletSchemas map[string]map[string]SchemaOption
	config         map[string]string

	isRootful         = false
	isSystemd         = false
	isPrintOnly       = false
	isVerbose         = false
	isFile            = false
	searchDir         = ""
	quadletSrcPath    = ""    // Path to the user's source directory containing quadlet folders or files
	useSubdirectories = true  // Default to installing quadlets in a subdirectory to keep them organized
	useSymbolicLinks  = false // Default to copying files for installation to avoid potential issues with source files being moved or deleted, but can be configured to use symbolic links for a more dynamic setup
	isReloadSystemd   = true  // Default to reloading systemd after installation to apply changes immediately
	//gInstallReplace   = false // Default to NOT replacing existing installed quadlets. User can remove first or specifically configure to replace.
	isRemoveVolumes   = true // Default to removing volumes on uninstall since they are often not needed after uninstall and can be left behind if not removed, but can be configured to keep volumes for data persistence.
	isRemoveNetworks  = true // Default to removing networks on uninstall since they are often not needed after uninstall and can be left behind if not removed, but can be configured to keep volumes for data persistence.
	systemdStartTmpl  = template.Must(template.New("systemdStart").Parse("systemctl {{.user}} start"))
	systemdStopTmpl   = template.Must(template.New("systemdStop").Parse("systemctl {{.user}} stop"))
	systemdStatusTmpl = template.Must(template.New("systemdStatus").Parse("systemctl {{.user}} status"))
	systemdReloadTmpl = template.Must(template.New("systemdReload").Parse("systemctl {{.user}} daemon-reload"))
	systemdLogsTmpl   = template.Must(template.New("systemdLogs").Parse("journalctl {{.user}} -xe"))
	quadletRootPath   = "/etc/containers/systemd"
	quadletUserPath   = "/etc/containers/systemd/users"
)

// Quadlet represents a parsed Quadlet file and its relationships.
type Quadlet struct {
	ID             string // Base name without extension (e.g., "my-app")
	Filepath       string
	Type           string // .container, .pod, .network, .volume, .kube
	Sections       map[string]map[string][]string
	Deps           []string          // IDs of other quadlets that must run first
	ParentPod      string            // If this is a container, the ID of its parent pod
	RestartPolicy  string            // [Service] Restart=
	KubernetesYaml string            // Path to original YAML for .kube
	GeneratedNames map[string]string // Key: name type, Value: specific name (useful for ps filters)
	ServiceName    string            // The name of the systemd unit (from quadlet file or default to <id>-<type>)
}

type Command struct {
	Label   string
	Spinner *spinner.Spinner
	Cmd     []string
	Output  string
	Error   error
}

func (c *Command) PreCmd() {
	c.Spinner = spinner.New(spinner.CharSets[14], 100*time.Millisecond) // Build our new spinner
	c.Spinner.Prefix = c.Label + " "
	c.Spinner.Start() // Start the spinner
}

func (c *Command) RunCmd() {
	cmd := exec.Command(c.Cmd[0], c.Cmd[1:]...)
	output, err := cmd.Output()
	c.Output = string(output)
	c.Error = err
}

func (c *Command) PostCmd() {
	c.Spinner.FinalMSG = fmt.Sprintf("%s... Done\n", c.Label)
	c.Spinner.Stop()
}

type Option struct {
	Key   string
	Value string
}

func assembleQuadletOptionsMap(options []SchemaOption) map[string]SchemaOption {
	optionsMap := make(map[string]SchemaOption)
	for _, option := range options {
		optionsMap[option.QuadletKey] = option
	}
	return optionsMap
}

func assemblePodmanOptionsMap(options []SchemaOption) map[string]SchemaOption {
	optionsMap := make(map[string]SchemaOption)
	for _, option := range options {
		optionsMap[option.PodmanKey] = option
	}
	return optionsMap
}

func GetQuadletOptionsMap(quadletType string) map[string]SchemaOption {
	var options []SchemaOption
	switch quadletType {
	case "container":
		options = GetContainerOptions()
	case "pod":
		options = GetPodOptions()
	case "network":
		options = GetNetworkOptions()
	case "volume":
		options = GetVolumeOptions()
	case "kube":
		options = GetKubeOptions()
	default:
		return nil
	}
	if options == nil {
		return nil
	}
	optionsMap := assembleQuadletOptionsMap(options)
	return optionsMap
}

func GetPodmanOptionsMap(quadletType string) map[string]SchemaOption {
	var options []SchemaOption
	switch quadletType {
	case "container":
		options = GetContainerOptions()
	case "pod":
		options = GetPodOptions()
	case "network":
		options = GetNetworkOptions()
	case "volume":
		options = GetVolumeOptions()
	case "kube":
		options = GetKubeOptions()
	default:
		return nil
	}
	if options == nil {
		return nil
	}
	optionsMap := assemblePodmanOptionsMap(options)
	return optionsMap
}

func main() {

	// Determine if running as root
	if os.Geteuid() == 0 {
		isRootful = true
	}

	initConfig()
	initSchemas()
	initFlags()

	quadlets := initQuadlets()

	// Topologically sort quadlets based on dependencies
	ordered, err := topologicalSort(quadlets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error determining ordering: %v\n", err)
		os.Exit(1)
	}

	subcommand := strings.ToLower(flag.Arg(0))

	// Route to appropriate subcommand handler
	switch subcommand {
	case "ps":
		handlePS(ordered)
	case "stats":
		handleStats(ordered)
	case "status":
		if isSystemd {
			handleSystemdStatus(ordered)
		} else {
			handlePS(ordered)
		}
	case "logs":
		if isSystemd {
			handleSystemdLogs(ordered)
		} else {
			fmt.Println("To view podman logs, use 'podman logs <container name or id>'")
			os.Exit(0)
		}
	case "images":
		handleImages(ordered)
	case "create":
		if isSystemd {
			handleSystemdCreate(ordered, searchDir)
		} else {
			handleCreate(ordered)
		}
	case "start":
		if isSystemd {
			handleSystemdStart(ordered, searchDir)
		} else {
			handleStart(ordered)
		}
	case "stop":
		if isSystemd {
			handleSystemdStop(ordered, false)
		} else {
			handleStop(ordered)
		}
	case "remove":
		if isSystemd {
			handleSystemdRemove(ordered, searchDir)
		} else {
			handleRemove(ordered)
		}
	case "pull":
		handlePull(ordered)
	case "list", "ls":
		handleList()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Orchestrator for Podman Quadlets (without systemd)\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [flags] <command> [directory]\n\n", ToolName)
	fmt.Fprintf(os.Stderr, "Flags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nCommands:\n")
	fmt.Fprintf(os.Stderr, "  pull     : Pull required images\n")
	fmt.Fprintf(os.Stderr, "  create   : Create resources (force re-creation), do not start. Use -s flag to generate quadlets.\n")
	fmt.Fprintf(os.Stderr, "  start    : Create (if missing) and start services. Use -s flag to start containers with systemd.\n")
	fmt.Fprintf(os.Stderr, "  stop     : Stop running services (do not remove). Use -s flag to stop containers run by systemd.\n")
	fmt.Fprintf(os.Stderr, "  remove   : Remove stopped resources. Use -s flag to remove generated quadlets.\n")
	fmt.Fprintf(os.Stderr, "  status   : Show current status. Use -s flag to see systemd status.\n")
	fmt.Fprintf(os.Stderr, "  logs     : Show logs of running containers. Use -s flag to view systemd logs.\n")
	fmt.Fprintf(os.Stderr, "  list, ls : List quadlets in the configured quadlet_path or systemd path if -s flag is used.\n")
	fmt.Fprintf(os.Stderr, "\nWrapper commands (filtered to defined resources):\n")
	fmt.Fprintf(os.Stderr, "  ps, stats, images\n")

}

// --- UTILITY FUNCTIONS ---

func initConfig() {
	// Read config
	config, err := getConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading config: %v\n", err)
		os.Exit(1)
	}
	if val, ok := config["use_subdirectories"]; ok && (val == "false" || val == "0") {
		useSubdirectories = false
	}
	if val, ok := config["use_symbolic_links"]; ok && (val == "true" || val == "1") {
		useSymbolicLinks = true
	}
	if val, ok := config["auto_reload_systemd"]; ok && (val == "false" || val == "0") {
		isReloadSystemd = false
	}
	if val, ok := config["remove_volumes"]; ok && (val == "false" || val == "0") {
		isRemoveVolumes = false
	}
	if val, ok := config["remove_networks"]; ok && (val == "false" || val == "0") {
		isRemoveNetworks = false
	}
	if val, ok := config["quadlet.src.path"]; ok && val != "" {
		quadletSrcPath = val
	}
	if val, ok := config["quadlet.root.path"]; ok && val != "" {
		quadletRootPath = val
	}
	if val, ok := config["quadlet.user.path"]; ok && val != "" {
		quadletUserPath = val
	}
	if val, ok := config["systemd.start"]; ok && val != "" {
		systemdStartTmpl = template.Must(template.New("systemdStart").Parse(val))
	}
	if val, ok := config["systemd.stop"]; ok && val != "" {
		systemdStopTmpl = template.Must(template.New("systemdStop").Parse(val))
	}
	if val, ok := config["systemd.status"]; ok && val != "" {
		systemdStatusTmpl = template.Must(template.New("systemdStatus").Parse(val))
	}
	if val, ok := config["systemd.reload"]; ok && val != "" {
		systemdReloadTmpl = template.Must(template.New("systemdReload").Parse(val))
	}
	if val, ok := config["systemd.logs"]; ok && val != "" {
		systemdLogsTmpl = template.Must(template.New("systemdLogs").Parse(val))
	}
}

func getConfig() (map[string]string, error) {

	config = make(map[string]string)
	var path string
	if isRootful {
		path = os.Getenv("QUADCTL_CONFIG_DIR")
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			err = fmt.Errorf("Invalid config path: %s\nWhen running as root, ensure QUADCTL_CONFIG_DIR is set and points to a valid directory.\nTo set root config same as user:\n\necho \"QUADCTL_CONFIG_DIR=$HOME/.config/quadctl\" | sudo tee -a /etc/environment > /dev/null", path)
			return nil, err
		}
	} else {
		path = os.Getenv("XDG_CONFIG_HOME")
		if path == "" {
			path = os.Getenv("HOME") + "/.config"
		}
		path = filepath.Join(path, "quadctl")
	}

	path = filepath.Join(path, "quadctl.conf")

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			config[key] = val
		}
	}
	return config, nil
}

func initSchemas() {
	//Get the schemas for each supported type
	quadletSchemas = map[string]map[string]SchemaOption{}
	quadletSchemas["volume"] = GetQuadletOptionsMap("volume")
	quadletSchemas["network"] = GetQuadletOptionsMap("network")
	quadletSchemas["container"] = GetQuadletOptionsMap("container")
	quadletSchemas["pod"] = GetQuadletOptionsMap("pod")
	quadletSchemas["kube"] = GetQuadletOptionsMap("kube")
}

func initFlags() {
	// Handle flags
	//rootfulOpt := flag.Bool("rootful", false, "Execute podman commands rootful (requires sudo/root access)")
	flag.BoolVar(&isPrintOnly, "print", false, "Print podman commands without executing")
	flag.BoolVar(&isPrintOnly, "p", false, "Print podman commands without executing")
	flag.BoolVar(&isVerbose, "verbose", false, "Print detailed information about command execution and warnings")
	flag.BoolVar(&isVerbose, "v", false, "Print detailed information about command execution and warnings")
	flag.BoolVar(&isFile, "file", false, "Specify that the provided path is a file rather than a directory (default: false)")
	flag.BoolVar(&isFile, "f", false, "Specify that the provided path is a file rather than a directory (default: false)")
	flag.BoolVar(&isSystemd, "systemd", false, "Use systemd for managing services (default: false)")
	flag.BoolVar(&isSystemd, "s", false, "Use systemd for managing services (default: false)")

	flag.Usage = printUsage
	flag.Parse()

	if flag.NArg() < 1 {
		printUsage()
		os.Exit(1)
	}

	// Determine search directory (optional path or CWD ... optional path may be relative to CWD or quadlets_path from config)
	// If no path is specified, use the current working directory
	var err error
	searchDir, err = os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting CWD: %v\n", err)
		os.Exit(1)
	}
	// If a path is specified, determine if relative to CWD or quadlets_path
	if flag.NArg() > 1 {
		tmp := flag.Arg(1)
		// If os.Stat returns no error, the path is absolute or valid relative to the current working directory
		if info, err := os.Stat(tmp); err == nil {
			//if a file was specified, get parent directory of the file
			if !info.IsDir() {
				searchDir = filepath.Dir(tmp)
			} else {
				searchDir, _ = filepath.Abs(tmp)
			}
			// Otherwise, look for specified directory path relative to the quadlets path
		} else {
			searchDir = filepath.Join(quadletSrcPath, tmp)
			// If the path is not found relative to the quadlets path or is not a directory, it's an error
			if info, err := os.Stat(searchDir); err == nil {
				//if a file was specified, get parent directory of the file
				if !info.IsDir() {
					searchDir = filepath.Dir(tmp)
				}
			} else {
				fmt.Fprintf(os.Stderr, "Error: %s not found\n", tmp)
				os.Exit(1)
			}
		}
	}
}

func initQuadlets() map[string]*Quadlet {
	// Discover, parse and resolve dependencies
	quadlets, err := discoverAndParseQuadlets(searchDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error processing quadlets in %s: %v\n", searchDir, err)
		os.Exit(1)
	}

	for _, q := range quadlets {
		// Special check for .kube and YAML existence before sorting
		if q.Type == ".kube" && q.KubernetesYaml != "" {
			if _, err := os.Stat(q.KubernetesYaml); os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "[WARN] %s: KubernetesYaml file not found: %s\n", q.Filepath, q.KubernetesYaml)
			}
		}
	}

	// If user specified the -f flag, the path provided should be a quadlet file, rather than directory. Only process the specified file and its dependencies.
	var selectedQuadlets []*Quadlet
	if isFile {
		// If a file was specified, find the corresponding quadlet
		tmp := strings.TrimSuffix(flag.Arg(1), filepath.Ext(flag.Arg(1)))
		selected := quadlets[tmp]
		if selected != nil {
			selectedQuadlets = append(selectedQuadlets, selected)
			if len(selected.Deps) > 0 {
				// Add dependencies to the selected quadlets
				for _, dep := range selected.Deps {
					if depQuadlet := quadlets[dep]; depQuadlet != nil {
						selectedQuadlets = append(selectedQuadlets, depQuadlet)
					}
				}
			}
			// Replace the original quadlets with the selected ones
			selectedQuadletsMap := make(map[string]*Quadlet)
			for _, q := range selectedQuadlets {
				selectedQuadletsMap[q.ID] = q
			}
			quadlets = selectedQuadletsMap
		}
	}

	return quadlets
}

// --- CORE LOGIC HANDLERS ---

// handleCreate generates and executes 'podman create' commands for all resources, but first checks if they exist and prints warnings if they do,
// suggesting to run 'remove' first if intent is to re-create. It also handles special cases like .kube and auto-restart configuration warnings.
func handleCreate(ordered []*Quadlet) {

	//Collect all warnings and print them together to avoid interleaving with commands
	warnings := []string{}
	commands := []Command{}

	for _, q := range ordered {
		//Only create if resource doesn't exist.
		if !resourceExists(q.Type, q.ID) {
			args, warns := generateCreateCommand(q)
			for _, w := range warns {
				warnings = append(warnings, fmt.Sprintf("[WARN] %s: %s\n", q.Filepath, w))
			}
			cmd := Command{
				Label:  fmt.Sprintf("Creating %s %s", q.Type, q.ID),
				Cmd:    args,
				Output: "",
				Error:  nil,
			}

			// Warn about auto-restart configuration and podman-restart.service requirement, if applicable
			if q.RestartPolicy == "always" || q.RestartPolicy == "on-failure" {
				restartWarning := fmt.Sprintln("# --- REMINDER: Auto Restart Configured ---")
				restartWarning += fmt.Sprintln("# Ensure podman-restart.service is enabled on the host to use this feature.")
				if isRootful {
					restartWarning += fmt.Sprintln("sudo systemctl enable --now podman-restart.service")
				} else {
					restartWarning += fmt.Sprintln("systemctl --user enable --now podman-restart.service")
				}
				warnings = append(warnings, restartWarning)
			}

			// Warn about AutoUpdate configuration, if applicable
			if q.GeneratedNames["auto_update"] != "" {
				warnings = append(warnings, fmt.Sprintf("[INFO] %s: Image AutoUpdate enabled (%s)\n", q.Filepath, q.GeneratedNames["auto_update"]))
			}

			commands = append(commands, cmd)

		} else {
			if isVerbose {
				warnings = append(warnings, fmt.Sprintf(" [INFO] %s %s already exists. To force re-creation of ALL resources, run 'quadctl remove' first.\n", q.Type, q.ID))
			}
		}
	}
	runCommands(commands, warnings)
}

// Common handling for dry run / verbose output and command execution for all handlers that generate commands.
func runCommands(commands []Command, warnings []string) {

	if isVerbose && len(warnings) > 0 {
		fmt.Println("\n# --- WARNINGS ---")
		for _, w := range warnings {
			fmt.Print(w)
		}
	}
	if isPrintOnly && len(commands) > 0 {
		fmt.Println("\n# --- DRY-RUN MODE: Commands that would be executed ---\n")
		for _, c := range commands {
			fmt.Printf("  %s\n", strings.Join(c.Cmd, " "))
		}
	} else if len(commands) > 0 {
		for _, c := range commands {
			c.PreCmd()
			c.RunCmd()
			c.PostCmd()
			if c.Error != nil && isVerbose {
				fmt.Fprintf(os.Stderr, "Error executing command '%s': %v\nOutput: %s\n", strings.Join(c.Cmd, " "), c.Error, c.Output)
			}
		}
	}
}

// Common handling for dry run / verbose output and command execution for all handlers that generate commands.
func processCommands(commands [][]string, warnings []string) {

	if isVerbose && len(warnings) > 0 {
		fmt.Println("\n# --- WARNINGS ---")
		for _, w := range warnings {
			fmt.Print(w)
		}
	}
	if isPrintOnly && len(commands) > 0 {
		fmt.Println("\n# --- DRY-RUN MODE: Commands that would be executed ---")
		for _, c := range commands {
			fmt.Printf("  %s\n", strings.Join(c, " "))
		}
	} else if len(commands) > 0 {
		for _, c := range commands {
			if isVerbose {
				fmt.Printf("=> Executing: %s\n", strings.Join(c, " "))
			}
			//ToDo - Print indication of actions for starting and stopping so user can follow the flow.
			//if slices.Contains(c, "stop") {
			//	fmt.Printf("=> Stopping %s %s...\n", q.Type, q.ID)
			//}
			_ = runCommand(c)
		}
	}
}

// Call handleCreate. Then start.
func handleStart(ordered []*Quadlet) {

	//Create, if necessary
	handleCreate(ordered)

	//Collect all warnings and print them together to avoid interleaving with commands
	warnings := []string{}
	commands := []Command{}

	//Start
	for _, q := range ordered {
		// Use generateStartupCommands
		cmd, warns := generateStartupCommand(q)
		for _, w := range warns {
			warnings = append(warnings, fmt.Sprintf("[WARN] %s: %s\n", q.Filepath, w))
		}
		if len(cmd) > 0 {
			commands = append(commands, Command{
				Label:  fmt.Sprintf("Starting %s %s", q.Type, q.ID),
				Cmd:    cmd,
				Output: "",
				Error:  nil,
			})
		}
	}
	runCommands(commands, warnings)
}

func handleStop(ordered []*Quadlet) {

	//Collect all warnings and print them together to avoid interleaving with commands
	warnings := []string{}
	commands := []Command{}

	// Reverse order for safe stopping
	for i := len(ordered) - 1; i >= 0; i-- {
		q := ordered[i]
		cmd := generateStopCommand(q)
		commands = append(commands, Command{
			Label:  fmt.Sprintf("Stopping %s %s", q.Type, q.ID),
			Cmd:    cmd,
			Output: "",
			Error:  nil,
		})
	}
	runCommands(commands, warnings)
}

func handleSystemdReload() {
	var buf bytes.Buffer
	data := map[string]string{}
	if !isRootful {
		data["user"] = "--user"
	}
	err := systemdReloadTmpl.Execute(&buf, data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing systemd reload template: %v\n", err)
		os.Exit(1)
	}
	command := strings.Fields(buf.String())
	cmd := Command{
		Label:  "Reloading systemd",
		Cmd:    command,
		Output: "",
		Error:  nil,
	}
	runCommands([]Command{cmd}, []string{})
}

func handleSystemdStart(ordered []*Quadlet, searchDir string) {
	//Ideally, call handleInstall if needed. How to check if the required systemd services are installed?
	/*
		❯ sudo podman quadlet list
		NAME                   UNIT NAME                    PATH ON DISK                                           STATUS      APPLICATION
		homebox-app.container  homebox-app.service          /etc/containers/systemd/homebox/homebox-app.container  Not loaded
		homebox-data.volume    homebox-data-volume.service  /etc/containers/systemd/homebox/homebox-data.volume    Not loaded
		homebox.pod            homebox-pod.service          /etc/containers/systemd/homebox/homebox.pod            Not loaded
	*/
	info, _ := listSystemdInstalledQuadlets(ordered)
	if len(info) < len(ordered) {
		handleSystemdCreate(ordered, searchDir)
	}

	// Reload quadlet definitions
	handleSystemdReload()

	// Start the systemd services
	var buf bytes.Buffer
	data := map[string]string{}
	if !isRootful {
		data["user"] = "--user"
	}
	err := systemdStartTmpl.Execute(&buf, data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing systemd start template: %v\n", err)
		os.Exit(1)
	}
	// Only start the pod and any loose containers
	for _, q := range ordered {
		if q.Type == ".container" && q.ParentPod == "" || q.Type == ".pod" {
			args := strings.Fields(buf.String())
			args = append(args, q.ServiceName)
			cmd := Command{
				Label:  fmt.Sprintf("Starting %s %s", q.Type, q.ID),
				Cmd:    args,
				Output: "",
				Error:  nil,
			}
			runCommands([]Command{cmd}, []string{})
		}
		// For networks and volumes, we rely on the fact that systemd will start them automatically when the containers that depend on them are started.
		// Ignoring .kube for now. Will require special handling (it's create+start in one 'play' command)
	}
}

func handleSystemdStop(ordered []*Quadlet, stopNetAndVol bool) {
	// Stop the systemd services
	var buf bytes.Buffer
	data := map[string]string{}
	if !isRootful {
		data["user"] = "--user"
	}
	err := systemdStopTmpl.Execute(&buf, data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing systemd stop template: %v\n", err)
		os.Exit(1)
	}

	cmds := []Command{}
	for _, q := range ordered {
		var args []string
		// Stop a container directly only if it is not part of a pod.
		if q.Type == ".container" && q.ParentPod == "" {
			args = strings.Fields(buf.String())
			args = append(args, q.ServiceName)
		} else if q.Type == ".pod" {
			// Stop the pod and any related containers.
			args = strings.Fields(buf.String())
			args = append(args, q.ServiceName)
		} else {
			// Stop network and volume services (Only used when called by handleUninstall. Ensures cleanup of volumes and networks).
			if stopNetAndVol && (q.Type == ".network" || q.Type == ".volume") {
				args = strings.Fields(buf.String())
				args = append(args, q.ServiceName)
			}
		}
		if len(args) == 0 {
			continue
		}
		cmd := Command{
			Label:  fmt.Sprintf("Systemd stopping %s %s", q.Type, q.ID),
			Cmd:    args,
			Output: "",
			Error:  nil,
		}
		cmds = append(cmds, cmd)
		// Ignoring .kube for now. Will require special handling (it's create+start in one 'play' command)
	}
	runCommands(cmds, []string{})
}

func handleSystemdStatus(ordered []*Quadlet) {
	var buf bytes.Buffer
	data := map[string]string{}
	if !isRootful {
		data["user"] = "--user"
	}
	err := systemdStatusTmpl.Execute(&buf, data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing systemd status template: %v\n", err)
		os.Exit(1)
	}

	args := strings.Fields(buf.String())
	for _, q := range ordered {
		args = append(args, q.ServiceName)
	}
	_ = runCommand(args)
}

func handleSystemdLogs(ordered []*Quadlet) {
	var buf bytes.Buffer
	data := map[string]string{}
	if !isRootful {
		data["user"] = "--user"
	}
	err := systemdLogsTmpl.Execute(&buf, data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing systemd logs: %v\n", err)
		os.Exit(1)
	}
	cmd := strings.Fields(buf.String())
	_ = runCommand(cmd)
}

func handleRemove(ordered []*Quadlet) {

	commands := []Command{}

	// Reverse order for safe removal
	for i := len(ordered) - 1; i >= 0; i-- {
		q := ordered[i]
		resType := q.Type
		resName := q.ID
		if q.Type == ".container" {
			resName = q.GeneratedNames["container"]
		}

		// kube down already removed things
		if resType == ".kube" {
			continue
		}

		fmt.Printf("=> Removing %s %s...\n", resType, resName)
		rmCmd := []string{"podman"}
		switch resType {
		case ".container":
			rmCmd = append(rmCmd, "container", "rm", "-f", resName)
		case ".pod":
			rmCmd = append(rmCmd, "pod", "rm", "-f", resName)
		case ".network":
			rmCmd = append(rmCmd, "network", "rm", resName)
		case ".volume":
			rmCmd = append(rmCmd, "volume", "rm", resName)
		}

		commands = append(commands, Command{
			Label:  fmt.Sprintf("Removing %s %s", resType, resName),
			Cmd:    rmCmd,
			Output: "",
			Error:  nil,
		})
	}
	runCommands(commands, nil)
}

func handlePull(ordered []*Quadlet) {
	images := make(map[string]bool)
	for _, q := range ordered {
		if q.Type == ".container" {
			if imgSec, ok := q.Sections["Container"]; ok {
				if imgList, ok := imgSec["Image"]; ok && len(imgList) > 0 {
					images[imgList[0]] = true
				}
			}
		}
		if q.Type == ".kube" && q.KubernetesYaml != "" {
			extracted, err := extractImagesFromYaml(q.KubernetesYaml)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error extracting images from YAML %s: %v\n", q.KubernetesYaml, err)
			}
			for _, img := range extracted {
				images[img] = true
			}
		}
	}

	for img := range images {
		//fmt.Printf("=> Pulling image: %s\n", img)
		_ = runCommand([]string{"podman", "pull", img})
	}
}

func handleSystemdCreate(ordered []*Quadlet, sourceDir string) {
	var targetDir string

	if isRootful {
		targetDir = quadletRootPath
	} else {
		targetDir = quadletUserPath
	}

	fileInfo, err := os.Stat(targetDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error accessing quadlet path %s: %v.\n", targetDir, err)
		if targetDir == quadletUserPath {
			fmt.Fprintf(os.Stderr, "If installing rootless quadlets to /etc/... or /run/... you may need to grant your user write permissions to the target directory.\n")
		}
		os.Exit(1)
	} else {
		if !fileInfo.IsDir() {
			fmt.Fprintf(os.Stderr, "Quadlet path %s is not a directory. Ensure the path points to a directory and try again.\n", targetDir)
			os.Exit(1)
		}
		perm := fileInfo.Mode().Perm()
		if perm&0200 != 0200 && perm&0020 != 0020 && perm&0002 != 0002 {
			fmt.Fprintf(os.Stderr, "Quadlet path %s is not writable. Ensure the directory is writable and try again.\n", targetDir)
			if targetDir == quadletUserPath {
				fmt.Fprintf(os.Stderr, "If installing rootless quadlets to /etc/containers/systemd... or /usr/share/containers/systemd... you may need to grant your user write permissions to the target directory.\n")
			}
			os.Exit(1)
		}
	}

	if isPrintOnly {
		fmt.Printf("=> [DRY-RUN] Would install quadlets to: %s\n", targetDir)
		if useSubdirectories {
			if useSymbolicLinks {
				fmt.Printf("  Would create symbolic link: %s -> %s\n", filepath.Join(targetDir, filepath.Base(sourceDir)), sourceDir)
			} else {
				fmt.Printf("  Would copy files to: %s\n", filepath.Join(targetDir, filepath.Base(sourceDir)))
			}
			return
		} else {
			if useSymbolicLinks {
				for _, q := range ordered {
					dest := filepath.Join(targetDir, filepath.Base(q.Filepath))
					fmt.Printf("  Would create symbolic link: %s -> %s\n", dest, q.Filepath)
				}
			} else {
				for _, q := range ordered {
					dest := filepath.Join(targetDir, filepath.Base(q.Filepath))
					fmt.Printf("  Would copy %s to %s\n", q.Filepath, dest)
				}
			}
		}
		return
	}

	if isVerbose {
		fmt.Printf("=> Installing quadlets to: %s\n", targetDir)
	}
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		//if err := runCommand([]string{prefix, "mkdir", "-p", targetDir}); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating target directory: %v\n", err)
		os.Exit(1)
	}

	// Dummy command to wrap multiple removal steps and print a simple message at the end.
	cmd := Command{
		Label:  fmt.Sprintf("Systemd installing quadlets to %s", targetDir),
		Cmd:    nil,
		Output: "",
		Error:  nil,
	}
	cmd.PreCmd()

	// Use links if configured to do so
	if useSymbolicLinks {
		if isVerbose {
			fmt.Println("Using symbolic links for installation.")
		}
		if useSubdirectories {
			// Link the entire source directory as a subdirectory in the target location to keep related quadlets together
			if err := os.Symlink(sourceDir, filepath.Join(targetDir, filepath.Base(sourceDir))); err != nil {
				//if err := runCommand([]string{prefix, "ln", "-s", sourceDir, filepath.Join(targetDir, filepath.Base(sourceDir))}); err != nil {
				fmt.Fprintf(os.Stderr, "Error linking target directory: %v\n", err)
				os.Exit(1)
			}
		} else {
			// Link the individual quadlet files directly into the target location
			for _, q := range ordered {
				dest := filepath.Join(targetDir, filepath.Base(q.Filepath))
				if isVerbose {
					fmt.Printf(" Linking %s to %s\n", q.Filepath, dest)
				}
				if err := os.Symlink(q.Filepath, dest); err != nil {
					//if err := runCommand([]string{prefix, "ln", "-s", q.Filepath, dest}); err != nil {
					fmt.Fprintf(os.Stderr, " Failed to link: %v\n", err)
				}

				// Also link drop-in directory if exists
				dropInDir := q.Filepath + ".d"
				if info, err := os.Stat(dropInDir); err == nil && info.IsDir() {
					destDropIn := dest + ".d"
					if isVerbose {
						fmt.Printf(" Linking directory %s to %s\n", dropInDir, destDropIn)
					}
					if err := os.Symlink(dropInDir, destDropIn); err != nil {
						//if err := runCommand([]string{prefix, "ln", "-s", dropInDir, destDropIn}); err != nil {
						fmt.Fprintf(os.Stderr, "  Failed to link dir: %v\n", err)
					}
				}
			}
		}
		// Otherwise copy files to the target directory using podman quadlet install
	} else {
		var destDropIn string

		/*
			//Use podman quadlet install if copying files (why? Because it handles setting correct SELinux labels on files which is required for systemd-managed quadlets to work properly. We could replicate this with chcon in the future if we want to support a non-podman install method, but using podman for the install step seems simpler and more robust for now.)
			if gInstallReplace {
				cmd := []string{"podman", "quadlet", "install", "--replace", sourceDir}
				_ = runCommandSilently(cmd)
			} else {
				cmd := []string{"podman", "quadlet", "install", sourceDir}
				_ = runCommandSilently(cmd)
			}
		*/

		// If the user configured to use a subdirectory to organize quadlets, we create the directory and move files after podman quadlet install step.
		if useSubdirectories {
			//Create the subdirectory at target location
			dest := filepath.Join(targetDir, filepath.Base(sourceDir))
			copyDir(sourceDir, dest)
		} else {
			for _, q := range ordered {
				copyFile(q.Filepath, filepath.Join(targetDir, filepath.Base(q.Filepath)))
			}
		}
		// Copy drop-in directories if exist
		for _, q := range ordered {
			dropInDir := q.Filepath + ".d"
			if info, err := os.Stat(dropInDir); err == nil && info.IsDir() {

				// Set dropInDir
				if useSubdirectories {
					destDropIn = filepath.Join(targetDir, filepath.Base(sourceDir), filepath.Base(q.Filepath)+".d")
				} else {
					destDropIn = filepath.Join(targetDir, filepath.Base(q.Filepath)+".d")
				}
				if isVerbose {
					fmt.Printf(" Copying directory %s to %s\n", dropInDir, destDropIn)
				}
				if err := copyDir(dropInDir, destDropIn); err != nil {
					fmt.Fprintf(os.Stderr, "  Failed to copy dir: %v\n", err)
				}
			}
		}
	}

	cmd.PostCmd()

	// Reload systemd to recognize the new quadlet services
	handleSystemdReload()
}

func handleSystemdRemove(ordered []*Quadlet, sourceDir string) {
	var targetDir string
	if isRootful {
		targetDir = quadletRootPath
	} else {
		targetDir = quadletUserPath
	}

	//reloadCmd := []string{"systemctl", prefix, "daemon-reload"}

	if isPrintOnly {
		fmt.Printf("=> [DRY-RUN] Would uninstall quadlets from: %s\n", targetDir)
		if useSymbolicLinks {
			if useSubdirectories {
				fmt.Printf("  Would remove symbolic link: %s -> %s\n", filepath.Join(targetDir, filepath.Base(sourceDir)), sourceDir)
			} else {
				for _, q := range ordered {
					dest := filepath.Join(targetDir, filepath.Base(q.Filepath))
					fmt.Printf("  Would remove symbolic link: %s -> %s\n", dest, q.Filepath)
				}
			}
			return
		} else {
			if useSubdirectories {
				fmt.Printf("  Would remove directory and all files from: %s\n", filepath.Join(targetDir, filepath.Base(sourceDir)))
			} else {
				for _, q := range ordered {
					dest := filepath.Join(targetDir, filepath.Base(q.Filepath))
					fmt.Printf("  Would remove %s from %s\n", q.Filepath, dest)
				}
			}
		}
		return
	}

	// Ensure any running services are stopped before uninstalling
	handleSystemdStop(ordered, true)

	// Dummy command to wrap multiple removal steps and print a simple message at the end.
	cmd := Command{
		Label:  fmt.Sprintf("Removing quadlets from %s", targetDir),
		Cmd:    nil,
		Output: "",
		Error:  nil,
	}
	cmd.PreCmd()

	//If targetDir exists, remove files.
	if info, err := os.Stat(targetDir); err == nil && info.IsDir() {
		if useSymbolicLinks {
			if useSubdirectories {
				//remove link to directory
				_ = os.Remove(filepath.Join(targetDir, filepath.Base(sourceDir)))
			} else {
				//remove individual file links
				for _, q := range ordered {
					dest := filepath.Join(targetDir, filepath.Base(q.Filepath))
					if err := os.Remove(dest); err != nil {
						fmt.Fprintf(os.Stderr, "Failed to remove %s: %v\n", dest, err)
					}
					// Also remove link to drop-in directory if exists
					dropInDir := dest + ".d"
					if info, err := os.Stat(dropInDir); err == nil && info.IsDir() {
						if err := os.Remove(dropInDir); err != nil {
							fmt.Fprintf(os.Stderr, "Failed to remove symlink to drop-in dir %s: %v\n", dropInDir, err)
						}
					}
				}
			}
		} else {
			// Use podman quadlet rm to remove installed quadlets if files were copied to target location.
			// quadctl always passes a directory to podman quadlet install, so all related quadlets are treated as one app and uninstalled if any are uninstalled.
			//cmd := []string{"podman", "quadlet", "rm", filepath.Base(ordered[0].Filepath)}
			//_ = runCommandSilently(cmd)
			// podman quadlet install does not recognize the subdirectory, so we have to remove it separately after quadlets are removed.
			if useSubdirectories {
				//remove directory and all files within
				_ = os.RemoveAll(filepath.Join(targetDir, filepath.Base(sourceDir)))
			} else {
				for _, q := range ordered {
					file := filepath.Join(targetDir, filepath.Base(q.Filepath))
					if info, err := os.Stat(file); err == nil && info.IsDir() {
						if err := os.Remove(file); err != nil {
							fmt.Fprintf(os.Stderr, "Failed to remove file %s: %v\n", file, err)
						}
					}
				}
			}
		}

		//Expressly remove volume and network resources that might be left behind
		for _, q := range ordered {
			if q.Type == ".volume" && isRemoveVolumes {
				if isVerbose {
					fmt.Printf("=> Removing volume %s...\n", q.ID)
				}
				//Default name has systemd- prefix. If non-default name was specified, use it, otherwise use default prefix.
				if volName := q.Sections["Volume"]["VolumeName"]; volName != nil {
					_ = runCommandSilently([]string{"podman", "volume", "rm", "-f", volName[0]})
				} else {
					_ = runCommandSilently([]string{"podman", "volume", "rm", "-f", "systemd-" + q.ID})
				}
			}
			if q.Type == ".network" && isRemoveNetworks {
				if isVerbose {
					fmt.Printf("=> Removing network %s...\n", q.ID)
				}
				//Default name has systemd- prefix. If non-default name was specified, use it, otherwise use default prefix.
				if networkName := q.Sections["Network"]["NetworkName"]; networkName != nil {
					_ = runCommandSilently([]string{"podman", "network", "rm", "-f", networkName[0]})
				} else {
					_ = runCommandSilently([]string{"podman", "network", "rm", "-f", "systemd-" + q.ID})
				}
			}
		}
	}

	cmd.PostCmd()

	// Reload systemd to ensure it picks up the changes after removal.
	handleSystemdReload()
}

func handlePS(ordered []*Quadlet) {

	psInfo, err := getContainerPS(ordered)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"CONTAINER ID", "NAME", "POD", "STATE", "PORTS", "IMAGE", "CREATED"})
	format := "2006-01-02 15:04:05.999999999 -0700 MST"
	for _, info := range psInfo {
		if len(info) >= 7 {

			createdDatetime, err := time.Parse(format, strings.TrimSpace(info[6]))
			createdDuration := "unknown"
			if err == nil {
				createdDuration = time.Since(createdDatetime).Round(time.Second).String() + " ago"
			}
			t.AppendRow(table.Row{
				strings.TrimSpace(info[0]),
				strings.TrimSpace(info[1]),
				strings.TrimSpace(info[2]),
				strings.TrimSpace(info[3]),
				strings.TrimSpace(info[4]),
				strings.TrimSpace(info[5]),
				strings.TrimSpace(createdDuration),
			})
		}
	}
	t.SetStyle(table.StyleColoredYellowWhiteOnBlack)
	t.Render()
}

func handleStats(ordered []*Quadlet) {

	psInfo, err := getContainerPS(ordered)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	//cmd := []string{"podman", "stats", "--no-stream"}
	cmd := []string{"podman", "stats"}

	for _, info := range psInfo {
		id := strings.TrimSpace(info[0])
		cmd = append(cmd, id)
	}

	err = runCommand(cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, " [ERROR] Command failed: %s\n", strings.Join(cmd, " "))
	}
}

func handleImages(ordered []*Quadlet) {

	//REPOSITORY                                 TAG         IMAGE ID      CREATED       SIZE
	cmd := []string{"podman", "images", "--noheading", "--filter", "reference=ADD_ID_HERE", "--format", "{{.Repository}},{{.Tag}},{{.ID}},{{.Created}},{{.Size}}"}
	imageInfo := [][]string{}

	// Fetch image info for each container
	psInfo, err := getContainerPS(ordered)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	if len(psInfo) > 0 {
		for _, info := range psInfo {
			name := strings.TrimSpace(info[5]) // IMAGE ID from ps output
			if len(name) < 12 {
				continue
			}
			cmd[4] = "reference=" + name
			output, err := runCommandCapture(cmd)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching image info for container %s: %v\n", info[0], err)
				continue
			}
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				parts := strings.Split(line, ",")
				if len(parts) >= 5 {
					imageInfo = append(imageInfo, parts)
				}
			}
		}
	} else {
		// If no containers are found, we can still fetch image info for the quadlet files
		fmt.Fprintf(os.Stderr, "No containers found, fetching image info from quadlet files...\n")
		for _, q := range ordered {
			// Images only pertain to containers and Kubernetes resources. Ignoring .kube for now...
			if q.Type == ".container" {
				if imgSec, ok := q.Sections["Container"]; ok {
					if imgList, ok := imgSec["Image"]; ok && len(imgList) > 0 {
						name := strings.TrimSpace(imgList[0]) // IMAGE ID from quadlet file
						if len(name) < 12 {
							continue
						}
						cmd[4] = "reference=" + name
						output, err := runCommandCapture(cmd)
						if err != nil {
							fmt.Fprintf(os.Stderr, "Error fetching image info for quadlet %s: %v\n", q.ID, err)
							continue
						}
						lines := strings.Split(output, "\n")
						for _, line := range lines {
							parts := strings.Split(line, ",")
							if len(parts) >= 5 {
								imageInfo = append(imageInfo, parts)
							}
						}
					}
				}
			}
		}
	}
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"REPOSITORY", "TAG", "IMAGE ID", "CREATED", "SIZE"})
	for _, info := range imageInfo {
		if len(info) >= 5 {
			t.AppendRow(table.Row{
				strings.TrimSpace(info[0]),
				strings.TrimSpace(info[1]),
				strings.TrimSpace(info[2]),
				strings.TrimSpace(info[3]),
				strings.TrimSpace(info[4]),
			})
		}
	}
	t.SetStyle(table.StyleColoredYellowWhiteOnBlack)
	t.Render()
}

func handleList() error {

	absPath := quadletSrcPath
	if isSystemd {
		if isRootful {
			absPath = quadletRootPath
		} else {
			absPath = quadletUserPath
		}
	}

	// Verify the path exists and is a directory
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("failed to stat path: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("provided path is not a directory")
	}

	lw := list.NewWriter()
	lw.SetStyle(list.StyleConnectedRounded)

	// Append the root directory name
	lw.AppendItem(absPath)

	// Start recursive rendering (root is level 1, its children are level 2)
	lw.Indent()
	err = appendDirItems(lw, absPath, 2)
	if err != nil {
		return err
	}
	lw.UnIndent()

	// Output the rendered list
	fmt.Println(lw.Render())
	return nil
}

// appendDirItems recursively traverses the directory and adds items to the list writer.
func appendDirItems(lw list.Writer, currentPath string, level int) error {
	entries, err := os.ReadDir(currentPath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		// Add the current file or directory to the list
		lw.AppendItem(entry.Name())

		// Nest deeper if it's a directory
		lw.Indent()
		if entry.IsDir() {
			nextPath := filepath.Join(currentPath, entry.Name())
			if err := appendDirItems(lw, nextPath, level+1); err != nil {
				return err
			}
		}
		lw.UnIndent()
	}

	return nil
}

// --- PARSING AND GENERATION LOGIC ---

func discoverAndParseQuadlets(searchDir string) (map[string]*Quadlet, error) {
	quadlets := make(map[string]*Quadlet)

	if info, err := os.Stat(searchDir); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("search path is not a directory: %s", searchDir)
	}

	dir, err := os.Open(searchDir)
	if err != nil {
		return nil, err
	}
	files, err := dir.Readdir(0)
	if err != nil {
		return nil, err
	}

	/*
	   Proposed modification to support single file format (.quadlet):
	   - Check for a .quadlet file extension (single file format for quadlets)
	   - If find a .quadlet file, create temp directory and extract quadlets into separate files with their indicated filenames and extensions
	   - Call discoverAndParseQuadlets recursively with the tempDir path
	   - Either return immediately after recursive call or continue to check for additional .quadlet files in the original searchDir
	   -   If continue processing, then you need to merge quadlet maps else will be overwriting quadlets from earlier processing.
	*/
	for _, f := range files {
		//fmt.Println(f.Name(), f.IsDir())
		path := filepath.Join(searchDir, f.Name())
		ext := filepath.Ext(path)
		if ".quadlet" == ext {
			tempDir, err := parseDotQuadlet(path)
			if err != nil {
				return nil, err
			}
			tempQuadlets, err := discoverAndParseQuadlets(tempDir)
			if err != nil {
				return nil, err
			}
			for k, v := range tempQuadlets {
				quadlets[k] = v
			}
		}
	}
	// Commenting out because assuming for now that any quadlet files should be processed.
	// However, it might make more sense to return early if found .quadlet file since all
	// related quadlets should be in the one file.
	//
	//if len(quadlets) > 0 {
	//	return quadlets, nil
	//}

	for _, f := range files {
		//fmt.Println(f.Name(), f.IsDir())
		path := filepath.Join(searchDir, f.Name())
		ext := filepath.Ext(path)
		if extensions[ext] {
			q, err := parseQuadlet(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, " Error parsing %s: %v\n", path, err)
			} else {
				quadlets[q.ID] = q
			}
		}
	}
	// 2nd pass: Extract dependencies (after all have IDs)
	for _, q := range quadlets {
		extractDependencies(q, quadlets)
	}

	return quadlets, nil
}

// Split quadlets by "---" on a separate new line and find filenames specified as "# FileName=<name>"
func parseDotQuadlet(path string) (string, error) {
	// For simplicity, we will just extract the .quadlet file into a temp directory with the same name as the .quadlet file (without extension) in the system temp directory.
	base := filepath.Base(path)
	id := strings.TrimSuffix(base, ".quadlet")
	tempDir := filepath.Join(os.TempDir(), id)

	//fmt.Printf("Temp Dir for .quadlet: %s\n", tempDir)

	// Create temp directory
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating temp directory: %v\n", err)
		return "", err
	}

	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	baseQuadletFilename := ""
	quadletText := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		//fmt.Println("READING: " + line)
		if strings.HasPrefix(line, "#") && strings.Contains(strings.TrimSpace(line), "Filename") {
			//fmt.Println("Found Filename...")
			prop := strings.Split(line, "=")
			if len(prop) > 1 {
				baseQuadletFilename = strings.TrimSpace(prop[1])
				//fmt.Println("Filename: " + baseQuadletFilename)
				continue
			}
		}
		// Save file when hit the separator
		if "---" == strings.TrimSpace(line) {
			//fmt.Println("SAVING file...")
			err := writeFile(filepath.Join(tempDir, baseQuadletFilename), quadletText)
			if err != nil {
				return "", err
			}
			baseQuadletFilename = ""
			quadletText = ""
			continue
		}
		quadletText += line + "\n"
	}

	// Save file if reach end of .quadlet file with a filename and quadlet text
	if len(baseQuadletFilename) > 0 && len(quadletText) > 0 {
		//fmt.Println("SAVING FINAL FILE...")
		err := writeFile(filepath.Join(tempDir, baseQuadletFilename), quadletText)
		if err != nil {
			return "", err
		}
	}

	return tempDir, nil
}

func parseQuadlet(path string) (*Quadlet, error) {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	id := strings.TrimSuffix(base, ext)

	q := &Quadlet{
		ID:             id,
		Filepath:       path,
		Type:           ext,
		Sections:       make(map[string]map[string][]string),
		GeneratedNames: make(map[string]string),
	}

	if err := parseIniFile(path, q); err != nil {
		return nil, err
	}

	// Set service name ... For container, use ServiceName if provided, otherwise {id}. For others, ServiceName or {id}-{type}
	var confServiceName string
	switch q.Type {
	case ".container":
		q.GeneratedNames["container"] = id
		vals := q.Sections["Container"]["ServiceName"]
		if len(vals) > 0 {
			confServiceName = vals[0]
		}
	case ".pod":
		vals := q.Sections["Pod"]["ServiceName"]
		if len(vals) > 0 {
			confServiceName = vals[0]
		}
	case ".volume":
		vals := q.Sections["Volume"]["ServiceName"]
		if len(vals) > 0 {
			confServiceName = vals[0]
		}
	case ".network":
		vals := q.Sections["Network"]["ServiceName"]
		if len(vals) > 0 {
			confServiceName = vals[0]
		}
	}
	if confServiceName == "" {
		if q.Type == ".container" {
			q.ServiceName = id
		} else {
			q.ServiceName = id + "-" + strings.TrimPrefix(q.Type, ".")
		}
	} else {
		q.ServiceName = confServiceName
	}

	// Merge systemd-style drop-ins from filename.d/*.conf
	dropInDir := path + ".d"
	if info, err := os.Stat(dropInDir); err == nil && info.IsDir() {
		files, _ := filepath.Glob(filepath.Join(dropInDir, "*.conf"))
		for _, f := range files {
			_ = parseIniFile(f, q) // Merge drop-ins silently
		}
	}

	// Specific checks based on parsing
	if contSec, ok := q.Sections["Container"]; ok {
		if val, ok := contSec["ContainerName"]; ok && len(val) > 0 {
			q.GeneratedNames["container"] = val[0]
		}
		if val, ok := contSec["Pod"]; ok && len(val) > 0 {
			q.ParentPod = strings.TrimSuffix(val[0], ".pod")
		}
		if val, ok := contSec["AutoUpdate"]; ok && len(val) > 0 {
			q.GeneratedNames["auto_update"] = val[0]
		}
	}

	if kubeSec, ok := q.Sections["Kube"]; ok {
		if val, ok := kubeSec["Yaml"]; ok && len(val) > 0 {
			q.KubernetesYaml = val[0]
		} else if val, ok := kubeSec["KubernetesYaml"]; ok && len(val) > 0 {
			// standard Quadlet key name
			q.KubernetesYaml = val[0]
		}
	}

	if svcSec, ok := q.Sections["Service"]; ok {
		if val, ok := svcSec["Restart"]; ok && len(val) > 0 {
			q.RestartPolicy = strings.ToLower(val[0])
		}
	}

	return q, nil
}

// Simple INI parser
func parseIniFile(path string, q *Quadlet) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	currentSection := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			if _, exists := q.Sections[currentSection]; !exists {
				q.Sections[currentSection] = make(map[string][]string)
			}
			continue
		}

		if currentSection != "" {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				q.Sections[currentSection][key] = append(q.Sections[currentSection][key], val)
			}
		}
	}
	return scanner.Err()
}

// extractDependencies determines implicit and explicit requirements
func extractDependencies(q *Quadlet, all map[string]*Quadlet) {
	depSet := make(map[string]bool)

	// Explicit Systemd dependencies [Unit] After=/Requires=
	if unit, ok := q.Sections["Unit"]; ok {
		for _, key := range []string{"Requires", "After"} {
			for _, val := range unit[key] {
				// Strip systemd.service ext, and optional quadlet ext, map back to ID
				id := strings.TrimSuffix(val, ".service")
				id = strings.TrimSuffix(id, filepath.Ext(id))
				if _, exists := all[id]; exists {
					depSet[id] = true
				}
			}
		}
	}

	// Implicit dependencies [Container/Pod] Network=/Volume=/Pod=
	if q.Type == ".container" {
		cont := q.Sections["Container"]
		if pod, ok := cont["Pod"]; ok && len(pod) > 0 {
			depSet[strings.TrimSuffix(pod[0], ".pod")] = true
		}

		for _, net := range cont["Network"] {
			id := strings.TrimSuffix(net, ".network")
			if _, exists := all[id]; exists {
				depSet[id] = true
			}
		}

		for _, vol := range cont["Volume"] {
			// Vol format source.volume:/path
			sourceVol := strings.TrimSuffix(strings.Split(vol, ":")[0], ".volume")
			if _, exists := all[sourceVol]; exists {
				depSet[sourceVol] = true
			}
		}
	} else if q.Type == ".pod" {
		podSec := q.Sections["Pod"]
		for _, net := range podSec["Network"] {
			id := strings.TrimSuffix(net, ".network")
			if _, exists := all[id]; exists {
				depSet[id] = true
			}
		}
	} else if q.Type == ".kube" && q.KubernetesYaml != "" {
		// Kube might rely on networks or volumes defined within but
		// they are usually Dynamic/internal. External dependency mapping is hard here.
	}

	deps := []string{}
	for k := range depSet {
		deps = append(deps, k)
	}
	q.Deps = deps
}

// generateCreateCommand creates the base 'podman ... create' string.
func generateCreateCommand(q *Quadlet) ([]string, []string) {
	var warnings []string
	var cmd []string

	// Warn about ignored sections
	for sec := range q.Sections {
		// standard systemd sections not used in CLI calls
		if sec == "Install" || sec == "Unit" {
			warnings = append(warnings, fmt.Sprintf("Ignoring entire [%s] section (Systemd specific)", sec))
		}
	}

	// Helper: Get raw PodmanArgs securely
	getRawPodmanArgs := func(section map[string][]string) []string {
		var args []string
		for _, argStr := range section["PodmanArgs"] {
			// Use Fields to parse space-separated flags
			args = append(args, strings.Fields(argStr)...)
		}
		return args
	}

	switch q.Type {
	case ".volume":
		//Get the schema for the volume type and use the PodmanTemplateParsed to format the podman option.
		options, ok := quadletSchemas["volume"]
		if !ok {
			warnings = append(warnings, "No volume schema found.")
			return cmd, warnings
		}
		cmd = append(cmd, "podman", "volume", "create")
		if volSec, ok := q.Sections["Volume"]; ok {
			cmd = append(cmd, getRawPodmanArgs(volSec)...)
			for k, vals := range volSec {
				for _, v := range vals {
					switch k {
					case "Type":
						continue // Type is not a Podman CLI option
					case "ServiceName":
						continue // ServiceName is for systemd and does not affect Podman CLI
					case "VolumeName":
						//cmd = append(cmd, "--name", v) // Not sure this is valid. May need to hold the value and append at the end after processing all options to avoid ordering issues with Podman CLI
						// The volume name is specified by the ID and added at the end of the command
						continue
					case "PodmanArgs": // Handled above
						continue
					default:
						var buf bytes.Buffer
						if opt, ok := options[k]; ok {
							option := Option{Key: opt.PodmanKey, Value: v}
							err := opt.PodmanTemplateParsed.Execute(&buf, option)
							if err != nil {
								warnings = append(warnings, fmt.Sprintf("Error formatting volume option %s: %v", k, err))
								continue
							}
							formatted := buf.String()
							// Use Fields to parse space-separated flags
							cmd = append(cmd, strings.Fields(formatted)...)

						} else {
							warnings = append(warnings, fmt.Sprintf("Quadlet volume option not defined: %s", k))
						}
					}
				}
			}
		}
		cmd = append(cmd, q.ID)

	case ".network":
		//Get the schema for the network type and use the PodmanTemplateParsed to format the podman option.
		options, ok := quadletSchemas["network"]
		if !ok {
			warnings = append(warnings, "No network schema found.")
			return cmd, warnings
		}
		cmd = append(cmd, "podman", "network", "create")
		if netSec, ok := q.Sections["Network"]; ok {
			cmd = append(cmd, getRawPodmanArgs(netSec)...)
			for k, vals := range netSec {
				for _, v := range vals {
					switch k {
					case "NetworkName":
						continue // NetworkName is for systemd and does not affect Podman CLI
					case "ServiceName":
						continue // ServiceName is for systemd and does not affect Podman CLI
					case "NetworkDeleteOnStop":
						continue // NetworkDeleteOnStop is for systemd and does not affect Podman CLI
					case "PodmanArgs": // Handled above
					default:
						var buf bytes.Buffer
						if opt, ok := options[k]; ok {
							option := Option{Key: opt.PodmanKey, Value: v}
							err := opt.PodmanTemplateParsed.Execute(&buf, option)
							if err != nil {
								warnings = append(warnings, fmt.Sprintf("Error formatting network option %s: %v", k, err))
								continue
							}
							formatted := buf.String()
							// Use Fields to parse space-separated flags
							cmd = append(cmd, strings.Fields(formatted)...)
						} else {
							warnings = append(warnings, fmt.Sprintf("Quadlet network option not defined: %s", k))
						}
					}
				}
			}
		}
		cmd = append(cmd, q.ID)

	case ".pod":
		//Get the schema
		options, ok := quadletSchemas["pod"]
		if !ok {
			warnings = append(warnings, "No pod schema found.")
			return cmd, warnings
		}

		cmd = append(cmd, "podman", "pod", "create", "--name", q.ID)
		if podSec, ok := q.Sections["Pod"]; ok {
			cmd = append(cmd, getRawPodmanArgs(podSec)...)
			for k, vals := range podSec {
				for _, v := range vals {
					switch k {
					case "ServiceName":
						continue // ServiceName is for systemd and does not affect Podman CLI
					case "PodmanArgs": // Handled above
					default:
						buf := bytes.Buffer{}
						if opt, ok := options[k]; ok {
							option := Option{Key: opt.PodmanKey, Value: v}
							err := opt.PodmanTemplateParsed.Execute(&buf, option)
							if err != nil {
								warnings = append(warnings, fmt.Sprintf("Error formatting pod option %s: %v", k, err))
								continue
							}
							formatted := buf.String()
							// Use Fields to parse space-separated flags
							cmd = append(cmd, strings.Fields(formatted)...)
						} else {
							warnings = append(warnings, fmt.Sprintf("Quadlet pod option not defined: %s", k))
						}
					}
				}
			}
		}

	case ".container":
		//Get the schema
		options, ok := quadletSchemas["container"]
		if !ok {
			warnings = append(warnings, "No container schema found.")
			return cmd, warnings
		}

		resName := q.GeneratedNames["container"]
		cmd = append(cmd, "podman", "container", "create", "--name", resName)

		// Map [Service] Restart= to --restart
		if q.RestartPolicy != "" {
			cmd = append(cmd, "--restart", q.RestartPolicy)
		}

		// Map [Container] AutoUpdate= to label
		//if q.GeneratedNames["auto_update"] != "" {
		//	cmd = append(cmd, "--label", "io.containers.autoupdate="+q.GeneratedNames["auto_update"])
		//}

		var image string
		var execCmd string
		if contSec, ok := q.Sections["Container"]; ok {
			cmd = append(cmd, getRawPodmanArgs(contSec)...)
			for k, vals := range contSec {

				if k == "Exec" {
					// Exec is a special case since it's not a Podman CLI option. Append command and args to the end of the create command.
					execCmd = strings.Join(vals, " ")
					continue
				}

				for _, v := range vals {
					switch k {
					case "Image":
						image = v
					case "ReloadCmd":
						continue // ReloadCmd is for systemd and does not affect Podman CLI
					case "ReloadSignal":
						continue // ReloadSignal is for systemd and does not affect Podman CLI
					case "ServiceName":
						continue // ServiceName is for systemd and does not affect Podman CLI
					case "StartWithPod":
						continue // StartWithPod is for systemd and does not affect Podman CLI
					case "Volume":
						volSource := strings.Split(v, ":")[0]
						cleanVol := strings.TrimSuffix(volSource, ".volume")
						mapped := strings.Replace(v, volSource, cleanVol, 1)
						cmd = append(cmd, "-v", mapped)
					case "Network":
						cmd = append(cmd, "--network", strings.TrimSuffix(v, ".network"))
					case "PodmanArgs": // Handled above
					default:
						var buf bytes.Buffer
						if opt, ok := options[k]; ok {
							if k == "Pod" {
								v = strings.TrimSuffix(v, ".pod")
							}
							option := Option{Key: opt.PodmanKey, Value: v}
							err := opt.PodmanTemplateParsed.Execute(&buf, option)
							if err != nil {
								warnings = append(warnings, fmt.Sprintf("Error formatting container option %s: %v", k, err))
								continue
							}
							formatted := buf.String()
							// Use Fields to parse space-separated flags
							cmd = append(cmd, strings.Fields(formatted)...)
						} else {
							warnings = append(warnings, fmt.Sprintf("Quadlet container option not defined: %s", k))
						}
					}
				}
			}
		}
		if image == "" {
			warnings = append(warnings, "No Image= specified in [Container]")
			image = "<MISSING_IMAGE>"
		}
		cmd = append(cmd, image)
		if execCmd != "" {
			// If a command to execute is specified for the quadlet, the equivalent podman create command will have it appended at the end.
			cmd = append(cmd, execCmd)
		}

	case ".kube":
		// .kube doesn't use standard create, it's 'kube play'
		if q.KubernetesYaml == "" {
			warnings = append(warnings, "No KubernetesYaml= specified in [Kube]")
			return nil, warnings
		}
		// Idempotency handles existence check for kube
		cmd = append(cmd, "podman", "kube", "play", q.KubernetesYaml)
	}

	return cmd, warnings
}

// generateStartupCommand creates necessary 'start' commands based on existence.
func generateStartupCommand(q *Quadlet) ([]string, []string) {
	cmd := []string{}
	warnings := []string{}
	resName := q.ID
	if q.Type == ".container" {
		resName = q.GeneratedNames["container"]
	}

	// Kube special handling (it's create+start in one 'play' command)
	if q.Type == ".kube" {
		createCmd, createWarns := generateCreateCommand(q)
		return createCmd, createWarns
	}

	// 3. Determine if we should start it
	shouldStart := true
	if q.Type == ".container" && q.ParentPod != "" {
		// Prompt: Create start commands ONLY for pods and loose containers
		shouldStart = false
	}

	if shouldStart {
		if q.Type == ".pod" {
			cmd = append(cmd, "podman", "pod", "start", resName)
		} else if q.Type == ".container" {
			cmd = append(cmd, "podman", "container", "start", resName)
		}
	} else if q.Type == ".container" {
		warnings = append(warnings, fmt.Sprintf(" [INFO] Container %s belongs to pod %s, it will start with the pod.\n", resName, q.ParentPod))
	}

	return cmd, warnings
}

func generateStopCommand(q *Quadlet) []string {
	cmd := []string{}
	resName := q.ID
	if q.Type == ".container" {
		resName = q.GeneratedNames["container"]
	}

	switch q.Type {
	case ".pod":
		cmd = append(cmd, []string{"podman", "pod", "stop", resName}...)
	case ".container":
		if q.ParentPod == "" {
			// loose container
			cmd = append(cmd, []string{"podman", "stop", resName}...)
		}
	case ".kube":
		// Stop the whole deployment/set of resources
		if q.KubernetesYaml != "" {
			cmd = append(cmd, []string{"podman", "kube", "down", q.KubernetesYaml}...)
		}
	}
	return cmd
}

// --- UTIL & TOPOLOGICAL SORT ---

func topologicalSort(quadlets map[string]*Quadlet) ([]*Quadlet, error) {
	var ordered []*Quadlet
	visited := make(map[string]bool)
	temp := make(map[string]bool)

	var visit func(nodeID string) error
	visit = func(nodeID string) error {
		if temp[nodeID] {
			return fmt.Errorf("circular dependency detected involving %s", nodeID)
		}
		if visited[nodeID] {
			return nil
		}

		temp[nodeID] = true
		for _, dep := range quadlets[nodeID].Deps {
			if _, exists := quadlets[dep]; !exists {
				return fmt.Errorf("%s depends on unknown quadlet %s", nodeID, dep)
			}
			if err := visit(dep); err != nil {
				return err
			}
		}
		temp[nodeID] = false
		visited[nodeID] = true
		ordered = append(ordered, quadlets[nodeID])
		return nil
	}

	for id := range quadlets {
		if !visited[id] {
			if err := visit(id); err != nil {
				return nil, err
			}
		}
	}
	return ordered, nil
}

func resourceExists(qType string, name string) bool {
	inspectCmd := []string{"podman"}
	switch qType {
	case ".container":
		inspectCmd = append(inspectCmd, "container", "inspect", name)
	case ".pod":
		inspectCmd = append(inspectCmd, "pod", "inspect", name)
	case ".network":
		inspectCmd = append(inspectCmd, "network", "inspect", name)
	case ".volume":
		inspectCmd = append(inspectCmd, "volume", "inspect", name)
	default:
		return false
	}
	return runCommandSilently(inspectCmd) == nil
}

// Very basic extraction by scanning for "image:" key in YAML
func extractImagesFromYaml(yamlPath string) ([]string, error) {
	images := []string{}
	file, err := os.Open(yamlPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		match := yamlImageRegex.FindStringSubmatch(line)
		if len(match) > 1 {
			img := strings.TrimSpace(match[1])
			if img != "" {
				images = append(images, img)
			}
		}
	}
	return images, scanner.Err()
}

func listSystemdInstalledQuadlets(ordered []*Quadlet) ([][]string, error) {
	cmd := []string{"podman", "quadlet", "list", "--format", "{{.Name}},{{.Path}},{{.Unit}},{{.Status}}"}
	output, err := runCommandCapture(cmd)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(output, "\n")
	var info [][]string
	for _, line := range lines {
		//fmt.Println(line)
		parts := strings.Split(line, ",")
		if len(parts) < 4 {
			continue
		}
		//filter for our quadlets
		for _, q := range ordered {
			name := filepath.Base(q.Filepath)
			if strings.TrimSpace(parts[0]) == name {
				info = append(info, parts)
				break
			}
		}
	}
	return info, nil
}

/*
CONTAINER ID  IMAGE       COMMAND     CREATED     STATUS      PORTS       NAMES
podman ps -a --format "{{.ID}},{{.Names}},{{.PodName}},{{.State}},{{.Ports}},{{.Image}},{{.Created}}"
*/
func getContainerPS(ordered []*Quadlet) ([][]string, error) {
	cmd := []string{"podman", "ps", "-a", "--format", "{{.ID}},{{.Names}},{{.PodName}},{{.Status}},{{.Ports}},{{.Image}},{{.Created}}"}
	output, err := runCommandCapture(cmd)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(output, "\n")
	var psInfo [][]string
	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) < 7 {
			continue
		}
		//filter for containers that match our quadlet definitions by name or parent pod
		for _, q := range ordered {
			if q.Type == ".container" && strings.HasSuffix(parts[1], q.GeneratedNames["container"]) || (q.ParentPod != "" && strings.HasSuffix(parts[2], q.ParentPod)) {
				psInfo = append(psInfo, parts)
				break
			}
		}
	}
	return psInfo, nil
}

// Execution and File Utils

func runCommand(args []string) error {
	if len(args) == 0 {
		return nil
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()

	return err
}

func runCommandSilently(args []string) error {
	//if isRootful && args[0] != "sudo" {
	//	args = append([]string{"sudo"}, args...)
	//}
	cmd := exec.Command(args[0], args[1:]...)
	// Discard output
	err := cmd.Run()
	return err
}

func runCommandCapture(args []string) (string, error) {
	//if isRootful && args[0] != "sudo" {
	//	args = append([]string{"sudo"}, args...)
	//}

	//fmt.Printf("=> Running command: %s\n", strings.Join(args, " "))

	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.Output()
	return string(output), err
}

func writeFile(path string, text string) error {
	//fmt.Println("WRITING: \n" + text)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(text)
	return err
}

func copyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()
	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	if err := os.Chmod(dst, 0644); err != nil {
		d.Close()
		return err
	}
	defer d.Close()
	_, err = io.Copy(d, s)
	return err
}

func copyDir(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, info.Mode()); err != nil {
		return err
	}
	files, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, f := range files {
		if f.IsDir() {
			continue // Don't handle recursive dirs for drop-ins
		}
		if err := copyFile(filepath.Join(src, f.Name()), filepath.Join(dst, f.Name())); err != nil {
			return err
		}
	}
	return nil
}
