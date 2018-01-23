package build

import (
	"io"

	"github.com/btcsuite/btclog"
)

// LogType is an indicating the type of logging specified by the build flag.
type LogType byte

const (
	// LogTypeNone indicates no logging.
	LogTypeNone LogType = iota

	// LogTypeStdOut all logging is written directly to stdout.
	LogTypeStdOut

	// LogTypeDefault logs to both stdout and a given io.PipeWriter.
	LogTypeDefault
)

// String returns a human readable identifier for the logging type.
func (t LogType) String() string {
	switch t {
	case LogTypeNone:
		return "none"
	case LogTypeStdOut:
		return "stdout"
	case LogTypeDefault:
		return "default"
	default:
		return "unknown"
	}
}

// LogWriter is a stub type whose behavior can be changed using the build flags
// "stdlog" and "nolog". The default behavior is to write to both stdout and the
// RotatorPipe. Passing "stdlog" will cause it only to write to stdout, and
// "nolog" implements Write as a no-op.
type LogWriter struct {
	// RotatorPipe is the write-end pipe for writing to the log rotator.  It
	// is written to by the Write method of the LogWriter type. This only
	// needs to be set if neither the stdlog or nolog builds are set.
	RotatorPipe *io.PipeWriter
}

// NewSubLogger constructs a new subsystem log from the current LogWriter
// implementation. This is primarily intended for use with stdlog, as the actual
// writer is shared amongst all instantiations.
func NewSubLogger(subsystem, levelStr string) btclog.Logger {
	backend := btclog.NewBackend(&LogWriter{})
	logger := backend.Logger(subsystem)

	level, _ := btclog.LevelFromString(levelStr)
	logger.SetLevel(level)

	return logger
}
