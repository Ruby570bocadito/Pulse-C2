//go:build !windows

package evasion

import "time"

// Init runs evasion techniques at agent startup.
// On non-Windows platforms this runs anti-sandbox/anti-debug checks.
// AntiSandbox, AntiDebug, and SleepWithJitter are defined in:
//   - anti_sandbox_unix.go (linux, darwin)
//   - anti_sandbox_other.go (freebsd, etc.)
func Init() {
	AntiSandbox()
	AntiDebug()
}

// UnhookNtdll is a no-op on non-Windows.
func UnhookNtdll() {}
type FirewallEvasion struct{}

func (fe *FirewallEvasion) AddFirewallRule() error { return nil }
func (fe *FirewallEvasion) AddPortRule(port int, protocol string) error { return nil }
func (fe *FirewallEvasion) RemoveFirewallRules() error { return nil }

func DisableWindowsDefender() error { return nil }
func ClearEventLogs() error { return nil }
func HideProcess() error { return nil }
func SpoofProcessName(legitName string) error { return nil }

// NetworkEvasion is a no-op on non-Windows.
type NetworkEvasion struct{}

func DisableLogging() error { return nil }
func ClearPrefetch() error { return nil }
func ClearRecentFiles() error { return nil }
func SpoofMACAddress(interfaceName, newMAC string) error { return nil }
func CreateHiddenUser(username, password string) error { return nil }
func DNSTunnel(dnsServer, domain string, data []byte) error { return nil }
func ICMPTunnel(target string, data []byte) error { return nil }
func HTTPSCovertChannel(url string, data []byte) error { return nil }

// Process techniques are no-op on non-Windows.
func ProcessHollowing(hostProcess string, payload []byte) error { return nil }
func ParentPIDSpoof(targetProcess string, parentPID uint32, payload []byte) error { return nil }
func ProcessGhosting(payload []byte, targetProcess string) error { return nil }
func ShellcodeExec(shellcode []byte) error { return nil }
func ModuleStomping(dllName string, shellcode []byte) error { return nil }

// StringCrypt is a no-op on non-Windows.
type StringCrypt struct{}
func NewStringCrypt() *StringCrypt { return &StringCrypt{} }
func (sc *StringCrypt) Encrypt(s string) []byte { return []byte(s) }
func (sc *StringCrypt) Decrypt(encrypted []byte) string { return string(encrypted) }

// APIHashing is a no-op on non-Windows.
type APIHashing struct{}
func NewAPIHashing() *APIHashing { return &APIHashing{} }
func (ah *APIHashing) ResolveAPI(dllName string, funcHash uint32) (uintptr, error) { return 0, nil }
func (ah *APIHashing) ResolveSyscallNumber(syscallHash uint32) (uint16, error) { return 0, nil }
func (ah *APIHashing) DirectSyscall(syscallNum uint16, args ...uintptr) (uintptr, error) { return 0, nil }

// BeaconOptimizer is a no-op on non-Windows.
type BeaconOptimizer struct{}
func NewBeaconOptimizer(base time.Duration, jitter float64) *BeaconOptimizer { return &BeaconOptimizer{} }
func (bo *BeaconOptimizer) NextInterval() time.Duration { return 0 }
func (bo *BeaconOptimizer) BurstSleep() {}
func (bo *BeaconOptimizer) Sleep() {}

// MemoryProtector is a no-op on non-Windows.
type MemoryProtector struct{}
func NewMemoryProtector() *MemoryProtector { return &MemoryProtector{} }
func (mp *MemoryProtector) Protect(addr uintptr, size uintptr) error { return nil }
func (mp *MemoryProtector) Execute(addr uintptr, size uintptr) error { return nil }
func (mp *MemoryProtector) Restore() error { return nil }
func ZeroMemory(addr uintptr, size int) {}
func SecureFree(addr uintptr, size int) {}
