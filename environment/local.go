package environment

func LocalEnvironment() EnvironmentCi {
	return EnvironmentCi{
		Provider: "local",
		Project:  "local",
		Branch:   "local",
		Tag:      "local",
		Url:      "local",
	}
}
