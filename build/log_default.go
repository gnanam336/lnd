// +build !stdlog,!nolog

package build

import "os"

const LoggingType = LogTypeDefault

func (w *LogWriter) Write(b []byte) (int, error) {
	os.Stdout.Write(b)
	w.RotatorPipe.Write(b)
	return len(b), nil
}
