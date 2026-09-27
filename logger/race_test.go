//go:build race

package logger

// The race detector instruments the standard library and drops sync.Pool
// items on purpose, so allocation counts under it aren't the logger's own.
const raceEnabled = true
