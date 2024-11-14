package environment

import "os"

func GitlabEnvironment() EnvironmentCi {
	return EnvironmentCi{
		Provider: "gitlab",
		Project:  os.Getenv("CI_PROJECT_NAME"),
		Branch:   os.Getenv("CI_COMMIT_REF_NAME"),
		Tag:      os.Getenv("CI_COMMIT_TAG"),
	}
}
