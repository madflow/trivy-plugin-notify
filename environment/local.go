package environment

func LocalEnvironment() EnvironmentCi {
	return EnvironmentCi{
		Provider: "local",
		Project:  "local",
		Ref:      "local",
		Url:      "local",
	}
}
