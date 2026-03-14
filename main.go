package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

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
}

// Global state
var (
	gRootful             = false
	gDryRun              = false
	gVerbose             = false
	gInstallSubdirectory = true // Default to installing quadlets in a subdirectory to keep them organized
	gInstallLinks        = true // Default to using symbolic links for installation to avoid file duplication and allow live updates
)

func main() {
	// 1. Define and parse flags
	rootfulOpt := flag.Bool("rootful", false, "Execute podman commands rootful (requires sudo/root access)")
	dryRunOpt := flag.Bool("dry-run", false, "Print podman commands and warnings without executing")
	verboseOpt := flag.Bool("verbose", false, "Print detailed information about command execution and warnings")

	flag.Usage = printUsage
	flag.Parse()

	if flag.NArg() < 1 {
		printUsage()
		os.Exit(1)
	}

	subcommand := strings.ToLower(flag.Arg(0))
	gRootful = *rootfulOpt
	gDryRun = *dryRunOpt
	gVerbose = *verboseOpt

	// 2. Determine search directory (optional path or CWD)
	searchDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting CWD: %v\n", err)
		os.Exit(1)
	}
	if flag.NArg() > 1 {
		tmp := flag.Arg(1)
		if info, err := os.Stat(tmp); err != nil || !info.IsDir() {
			fmt.Fprintf(os.Stderr, "Error: %s is not a directory\n", tmp)
			os.Exit(1)
		}
		searchDir, _ = filepath.Abs(tmp)
	}

	// 3. Discover, parse and resolve dependencies
	quadlets, err := discoverAndParseQuadlets(searchDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error processing quadlets in %s: %v\n", searchDir, err)
		os.Exit(1)
	}

	// Special check for .kube and YAML existence before sorting
	for _, q := range quadlets {
		if q.Type == ".kube" && q.KubernetesYaml != "" {
			if _, err := os.Stat(q.KubernetesYaml); os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "[WARN] %s: KubernetesYaml file not found: %s\n", q.Filepath, q.KubernetesYaml)
			}
		}
	}

	// 4. Topologically sort quadlets based on dependencies
	ordered, err := topologicalSort(quadlets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error determining ordering: %v\n", err)
		os.Exit(1)
	}

	// 5. Route to appropriate subcommand handler
	switch subcommand {
	case "ps":
		handlePS(ordered)
	case "stats":
		handleStats(ordered)
	case "images":
		handleImages(ordered)
	case "create":
		handleCreate(ordered)
	case "up":
		handleUp(ordered)
	case "down":
		handleDown(ordered)
	case "remove":
		handleRemove(ordered)
	case "pull":
		handlePull(quadlets)
	case "install":
		handleInstall(ordered, searchDir)
	case "uninstall":
		handleUninstall(ordered, searchDir)
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
	fmt.Fprintf(os.Stderr, "  pull    : Pull required images\n")
	fmt.Fprintf(os.Stderr, "  create  : Create resources (force re-creation), do not start\n")
	fmt.Fprintf(os.Stderr, "  up      : Create (if missing) and start services\n")
	fmt.Fprintf(os.Stderr, "  down    : Stop running services (do not remove)\n")
	fmt.Fprintf(os.Stderr, "  remove  : Remove stopped resources\n")
	fmt.Fprintf(os.Stderr, "  install : Copy files to systemd dirs and print systemd instructions\n")
	fmt.Fprintf(os.Stderr, "  uninstall : Remove files in systemd dirs\n")
	fmt.Fprintf(os.Stderr, "\nWrapper commands (filtered to defined resources):\n")
	fmt.Fprintf(os.Stderr, "  ps, stats, images\n")
}

// --- CORE LOGIC HANDLERS ---

// handleCreate generates and executes 'podman create' commands for all resources, but first checks if they exist and prints warnings if they do,
// suggesting to run 'remove' first if intent is to re-create. It also handles special cases like .kube and auto-restart configuration warnings.
func handleCreate(ordered []*Quadlet) {
	//Collect all warnings and print them together to avoid interleaving with commands
	warnings := []string{}
	commands := [][]string{}

	for _, q := range ordered {

		//Only create if resource doesn't exist.
		if !resourceExists(q.Type, q.ID) {

			cmd, warns := generateCreateCommand(q)
			for _, w := range warns {
				warnings = append(warnings, fmt.Sprintf("[WARN] %s: %s\n", q.Filepath, w))
			}

			// Warn about auto-restart configuration and podman-restart.service requirement, if applicable
			if q.RestartPolicy == "always" || q.RestartPolicy == "on-failure" {
				restartWarning := fmt.Sprintln("# --- REMINDER: Auto Restart Configured ---")
				restartWarning += fmt.Sprintln("# Ensure podman-restart.service is enabled on the host to use this feature.")
				if gRootful {
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
			if gVerbose || gDryRun {
				warnings = append(warnings, fmt.Sprintf(" [INFO] %s %s already exists. To force re-creation of ALL resources, run 'quadctl remove' first.\n", q.Type, q.ID))
			}
		}
	}
	processCommands(commands, warnings)
}

// Common handling for dry run / verbose output and command execution for all handlers that generate commands.
func processCommands(commands [][]string, warnings []string) {

	if gVerbose && len(warnings) > 0 {
		fmt.Println("\n# --- WARNINGS ---")
		for _, w := range warnings {
			fmt.Print(w)
		}
	}
	if gDryRun && len(commands) > 0 {
		fmt.Println("\n# --- DRY-RUN MODE: Commands that would be executed ---")
		for _, c := range commands {
			fmt.Printf("  %s\n", strings.Join(c, " "))
		}
	} else if len(commands) > 0 {
		for _, c := range commands {
			if gVerbose {
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
func handleUp(ordered []*Quadlet) {

	//Create, if necessary
	handleCreate(ordered)

	//Collect all warnings and print them together to avoid interleaving with commands
	warnings := []string{}
	commands := [][]string{}

	//Start
	for _, q := range ordered {
		// Use generateStartupCommands
		cmd, warns := generateStartupCommand(q)
		for _, w := range warns {
			warnings = append(warnings, fmt.Sprintf("[WARN] %s: %s\n", q.Filepath, w))
		}
		if len(cmd) > 0 {
			commands = append(commands, cmd)
		}
	}
	processCommands(commands, warnings)
}

func handleDown(ordered []*Quadlet) {

	//Collect all warnings and print them together to avoid interleaving with commands
	warnings := []string{}
	commands := [][]string{}

	// Reverse order for safe stopping
	for i := len(ordered) - 1; i >= 0; i-- {
		q := ordered[i]
		cmd := generateStopCommand(q)
		commands = append(commands, cmd)
	}
	processCommands(commands, warnings)
}

func handleRemove(ordered []*Quadlet) {

	//ToDo - Check if resources are running and stop them first if necessary.

	commands := [][]string{}

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
		//_ = runCommand(rmCmd)
		commands = append(commands, rmCmd)
	}
	processCommands(commands, nil)
}

func handlePull(quadlets map[string]*Quadlet) {
	images := make(map[string]bool)
	for _, q := range quadlets {
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
		fmt.Printf("=> Pulling image: %s\n", img)
		_ = runCommand([]string{"podman", "pull", img})
	}
}

func handleInstall(ordered []*Quadlet, sourceDir string) {
	var targetDir string
	if gRootful {
		targetDir = "/etc/containers/systemd"
	} else {
		targetDir = filepath.Join(os.Getenv("HOME"), ".config/containers/systemd")
	}

	fmt.Printf("=> Installing quadlets to: %s\n", targetDir)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating target directory: %v\n", err)
		os.Exit(1)
	}

	// Check config to determine if user prefers to deploy quadlets in folders to keep related quadlets together (default) or directly deploy to the target systemd folder.
	if gInstallSubdirectory {
		if gInstallLinks {
			os.Symlink(sourceDir, filepath.Join(targetDir, filepath.Base(sourceDir)))
		} else {
			dest := filepath.Join(targetDir, filepath.Base(sourceDir))
			if err := os.MkdirAll(dest, 0755); err != nil {
				fmt.Fprintf(os.Stderr, "Error creating directory: %v\n", err)
				os.Exit(1)
			}

			// Copy all quadlet files and their drop-in directories to the new directory
			for _, q := range ordered {
				src := q.Filepath
				dest := filepath.Join(targetDir, filepath.Base(sourceDir), filepath.Base(q.Filepath))
				fmt.Printf(" Copying %s to %s\n", src, dest)
				if err := copyFile(src, dest); err != nil {
					fmt.Fprintf(os.Stderr, " Failed to copy: %v\n", err)
				}
				// Also copy drop-in directory if exists
				dropInDir := q.Filepath + ".d"
				if info, err := os.Stat(dropInDir); err == nil && info.IsDir() {
					destDropIn := dest + ".d"
					fmt.Printf(" Copying directory %s to %s\n", dropInDir, destDropIn)
					if err := copyDir(dropInDir, destDropIn); err != nil {
						fmt.Fprintf(os.Stderr, "  Failed to copy dir: %v\n", err)
					}
				}
			}
		}
	} else {
		// Install symbolic links to the target quadlet directory instead of copying the files.
		if gInstallLinks {

			fmt.Println("Using symbolic links for installation.")
			for _, q := range ordered {
				dest := filepath.Join(targetDir, filepath.Base(q.Filepath))
				fmt.Printf(" Linking %s to %s\n", q.Filepath, dest)
				if err := os.Symlink(q.Filepath, dest); err != nil {
					fmt.Fprintf(os.Stderr, " Failed to link: %v\n", err)
				}

				// Also copy drop-in directory if exists
				dropInDir := q.Filepath + ".d"
				if info, err := os.Stat(dropInDir); err == nil && info.IsDir() {
					destDropIn := dest + ".d"
					fmt.Printf(" Linking directory %s to %s\n", dropInDir, destDropIn)
					if err := os.Symlink(dropInDir, destDropIn); err != nil {
						fmt.Fprintf(os.Stderr, "  Failed to link dir: %v\n", err)
					}
				}
			}

		} else {
			copiedFiles := []string{}
			for _, q := range ordered {
				dest := filepath.Join(targetDir, filepath.Base(q.Filepath))
				fmt.Printf(" Copying %s to %s\n", q.Filepath, dest)
				if err := copyFile(q.Filepath, dest); err != nil {
					fmt.Fprintf(os.Stderr, " Failed to copy: %v\n", err)
				} else {
					copiedFiles = append(copiedFiles, filepath.Base(q.Filepath))
				}

				// Also copy drop-in directory if exists
				dropInDir := q.Filepath + ".d"
				if info, err := os.Stat(dropInDir); err == nil && info.IsDir() {
					destDropIn := dest + ".d"
					fmt.Printf(" Copying directory %s to %s\n", dropInDir, destDropIn)
					if err := copyDir(dropInDir, destDropIn); err != nil {
						fmt.Fprintf(os.Stderr, "  Failed to copy dir: %v\n", err)
					}
				}
			}
		}
	}
	// 2. Print systemd instructions
	serviceNames := []string{}
	for _, q := range ordered {
		ext := filepath.Ext(q.Filepath)
		if ext == ".kube" {
			fmt.Fprintf(os.Stderr, "[INFO] .kube installs use the generic `podman-kube@` service\n")
			continue
		}
		// Convert myapp.container to myapp.service
		svc := strings.TrimSuffix(q.Filepath, ext) + ".service"
		serviceNames = append(serviceNames, svc)
	}

	prefix := ""
	if !gRootful {
		prefix = "--user "
	}

	fmt.Println("\n# --- SYSTEMD INSTRUCTIONS ---")
	fmt.Println("# Quadlets installed. Execute the following commands to enable via systemd:")
	fmt.Printf("\nsystemctl %sdaemon-reload\n", prefix)
	if len(serviceNames) > 0 {
		fmt.Printf("systemctl %senable --now %s\n", prefix, strings.Join(serviceNames, " "))
	}
}

func handleUninstall(ordered []*Quadlet, sourceDir string) {
	var targetDir string
	if gRootful {
		targetDir = "/etc/containers/systemd"
	} else {
		targetDir = filepath.Join(os.Getenv("HOME"), ".config/containers/systemd")
	}

	//If targetDir exists, remove files.
	if info, err := os.Stat(targetDir); err == nil && info.IsDir() {
		if gInstallSubdirectory {
			if gInstallLinks {
				//remove link to directory
				_ = os.Remove(filepath.Join(targetDir, filepath.Base(sourceDir)))
			} else {
				//remove directory and all files within
				_ = os.RemoveAll(filepath.Join(targetDir, filepath.Base(sourceDir)))
			}
		} else {
			//remove individual files
			for _, q := range ordered {
				dest := filepath.Join(targetDir, filepath.Base(q.Filepath))
				if err := os.Remove(dest); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to remove %s: %v\n", dest, err)
				}
				// Also remove drop-in directory if exists
				dropInDir := dest + ".d"
				if info, err := os.Stat(dropInDir); err == nil && info.IsDir() {
					if err := os.RemoveAll(dropInDir); err != nil {
						fmt.Fprintf(os.Stderr, "Failed to remove drop-in dir %s: %v\n", dropInDir, err)
					}
				}
			}
		}
	}
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

	// Defaults based on extension
	if ext == ".container" {
		q.GeneratedNames["container"] = id
	}

	if err := parseIniFile(path, q); err != nil {
		return nil, err
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
		cmd = append(cmd, "podman", "volume", "create")
		if volSec, ok := q.Sections["Volume"]; ok {
			cmd = append(cmd, getRawPodmanArgs(volSec)...)
			for k := range volSec {
				if k != "PodmanArgs" {
					warnings = append(warnings, fmt.Sprintf("Ignored [Volume] key: %s", k))
				}
			}
		}
		cmd = append(cmd, q.ID)

	case ".network":
		cmd = append(cmd, "podman", "network", "create")
		if netSec, ok := q.Sections["Network"]; ok {
			cmd = append(cmd, getRawPodmanArgs(netSec)...)
			for k, vals := range netSec {
				for _, v := range vals {
					switch k {
					case "Subnet":
						cmd = append(cmd, "--subnet", v)
					case "Gateway":
						cmd = append(cmd, "--gateway", v)
					case "Label":
						cmd = append(cmd, "--label", v)
					case "PodmanArgs": // Handled above
					default:
						warnings = append(warnings, fmt.Sprintf("Ignored [Network] key: %s", k))
					}
				}
			}
		}
		cmd = append(cmd, q.ID)

	case ".pod":
		cmd = append(cmd, "podman", "pod", "create", "--name", q.ID)
		if podSec, ok := q.Sections["Pod"]; ok {
			cmd = append(cmd, getRawPodmanArgs(podSec)...)
			for k, vals := range podSec {
				for _, v := range vals {
					switch k {
					case "PublishPort":
						cmd = append(cmd, "-p", v)
					case "Network":
						cmd = append(cmd, "--network", strings.TrimSuffix(v, ".network"))
					case "PodmanArgs": // Handled above
					default:
						warnings = append(warnings, fmt.Sprintf("Ignored [Pod] key: %s", k))
					}
				}
			}
		}

	case ".container":
		resName := q.GeneratedNames["container"]
		cmd = append(cmd, "podman", "container", "create", "--name", resName)

		// Map [Service] Restart= to --restart
		if q.RestartPolicy != "" {
			cmd = append(cmd, "--restart", q.RestartPolicy)
		}

		// Map [Container] AutoUpdate= to label
		if q.GeneratedNames["auto_update"] != "" {
			cmd = append(cmd, "--label", "io.containers.autoupdate="+q.GeneratedNames["auto_update"])
		}

		var image string
		if contSec, ok := q.Sections["Container"]; ok {
			cmd = append(cmd, getRawPodmanArgs(contSec)...)
			for k, vals := range contSec {
				for _, v := range vals {
					switch k {
					case "Image":
						image = v
					case "Environment":
						cmd = append(cmd, "-e", v)
					case "PublishPort":
						cmd = append(cmd, "-p", v)
					case "Volume":
						volSource := strings.Split(v, ":")[0]
						cleanVol := strings.TrimSuffix(volSource, ".volume")
						mapped := strings.Replace(v, volSource, cleanVol, 1)
						cmd = append(cmd, "-v", mapped)
					case "Network":
						cmd = append(cmd, "--network", strings.TrimSuffix(v, ".network"))
					case "Pod":
						cmd = append(cmd, "--pod", strings.TrimSuffix(v, ".pod"))
					case "ContainerName", "PodmanArgs", "AutoUpdate": // Handled above or ignored
					default:
						warnings = append(warnings, fmt.Sprintf("Ignored [Container] key: %s", k))
					}
				}
			}
		}
		if image == "" {
			warnings = append(warnings, "No Image= specified in [Container]")
			image = "<MISSING_IMAGE>"
		}
		cmd = append(cmd, image)

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

// Execution and File Utils

func runCommand(args []string) error {
	if len(args) == 0 {
		return nil
	}
	if gRootful && args[0] != "sudo" {
		args = append([]string{"sudo"}, args...)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, " [ERROR] Command failed: %s\n", strings.Join(args, " "))
	}
	return err
}

func runCommandSilently(args []string) error {
	if gRootful && args[0] != "sudo" {
		args = append([]string{"sudo"}, args...)
	}
	cmd := exec.Command(args[0], args[1:]...)
	// Discard output
	err := cmd.Run()
	return err
}

func runCommandCapture(args []string) (string, error) {
	if gRootful && args[0] != "sudo" {
		args = append([]string{"sudo"}, args...)
	}

	//fmt.Printf("=> Running command: %s\n", strings.Join(args, " "))

	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.Output()
	return string(output), err
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
			if q.Type == ".container" && q.GeneratedNames["container"] == parts[1] || (q.ParentPod != "" && q.ParentPod == parts[2]) {
				psInfo = append(psInfo, parts)
				break
			}
		}
	}
	return psInfo, nil
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

	if gRootful {
		cmd = append([]string{"sudo"}, cmd...)
	}

	err = runCommand(cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, " [ERROR] Command failed: %s\n", strings.Join(cmd, " "))
	}
}

func handleImages(ordered []*Quadlet) {

	psInfo, err := getContainerPS(ordered)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	//REPOSITORY                                 TAG         IMAGE ID      CREATED       SIZE
	cmd := []string{"podman", "images", "--noheading", "--filter", "reference=ADD_ID_HERE", "--format", "{{.Repository}},{{.Tag}},{{.ID}},{{.Created}},{{.Size}}"}
	imageInfo := [][]string{}

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
