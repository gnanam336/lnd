package build

// BuildType is an enum specifying the deployment to compile.
type BuildType byte

const (
	// Development a standard compilation with logs disabled by default.
	Development BuildType = iota

	// Testing special deployment to simulate production with testing hooks.
	Testing

	// Production is a deployment with extra sanity checks for real lyfe.
	Production
)

// String returns a human readable name for a build type.
func (b BuildType) String() string {
	switch b {
	case Development:
		return "development"
	case Testing:
		return "testing"
	case Production:
		return "production"
	default:
		return "unknown"
	}
}
