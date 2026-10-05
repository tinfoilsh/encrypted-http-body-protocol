//go:build linux

package main

import "syscall"

func peakRSSBytes() int64 {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return ru.Maxrss << 10
}
