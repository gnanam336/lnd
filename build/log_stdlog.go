// +build stdlog

package build

import "os"

const LoggingType = LogTypeStdOut

func (w *LogWriter) Write(b []byte) (int, error) {
	os.Stdout.Write(b)
	return len(b), nil
}
