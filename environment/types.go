package environment

type EnvironmentCi struct {
	Provider string
	Project  string
	Branch   string
	Tag      string
	Url      string
}
