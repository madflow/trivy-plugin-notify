package environment

import "os"

func GitlabEnvironment() EnvironmentCi {
	return EnvironmentCi{
		Provider: "gitlab",
		Project:  os.Getenv("CI_PROJECT_NAME"),
		Ref:      os.Getenv("CI_COMMIT_REF_NAME"),
		Url:      os.Getenv("CI_PROJECT_URL"),
	}
}
