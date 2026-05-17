//go:build !windows && !linux && !darwin

package evasion

import "time"

// AntiSandbox stub for unsupported platforms (freebsd, etc.)
func AntiSandbox() bool {
	return true // Assume real machine if we can't check
}

// AntiDebug stub for unsupported platforms (freebsd, etc.)
func AntiDebug() bool {
	return true // Assume no debugger if we can't check
}

// SleepWithJitter stub for unsupported platforms.
func SleepWithJitter(min, max time.Duration) {
	time.Sleep((min + max) / 2)
}
