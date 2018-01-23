package build

// Commit stores the current commit hash of this build, this should be set using
// the -ldflags during compilation.
var Commit string
