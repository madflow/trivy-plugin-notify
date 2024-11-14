package environment

import "os"

func DetectEnvironmentCi() EnvironmentCi {
	if DetectInCi() {
		if DetectGitlabCi() {
			return GitlabEnvironment()
		}
	}
	return LocalEnvironment()
}

func DetectInCi() bool {
	return os.Getenv("CI") != ""
}

func DetectGitlabCi() bool {
	return os.Getenv("GITLAB_CI") != ""
}
