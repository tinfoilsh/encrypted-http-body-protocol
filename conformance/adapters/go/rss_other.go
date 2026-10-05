//go:build !darwin && !linux

package main

// No measurement here: report nothing rather than 0, so the harness's
// buffering check is visibly absent instead of silently satisfied.
func peakRSSBytes() (int64, bool) { return 0, false }
