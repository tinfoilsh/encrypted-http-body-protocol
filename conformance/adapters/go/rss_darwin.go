//go:build darwin

package main

import "syscall"

func peakRSSBytes() (int64, bool) {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return ru.Maxrss, true
}
