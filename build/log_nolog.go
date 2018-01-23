// +build nolog

package build

const LoggingType = LogTypeNone

func (w *LogWriter) Write(b []byte) (int, error) {
	return len(b), nil
}
