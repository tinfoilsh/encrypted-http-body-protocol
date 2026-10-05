//go:build !darwin && !linux

package main

func peakRSSBytes() int64 { return 0 }
