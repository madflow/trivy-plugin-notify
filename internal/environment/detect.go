package environment

import "os"

func DetectEnvironmentCi() EnvironmentCi {
	if DetectInCi() {
		if DetectGitlabCi() {
			return GitlabEnvironment()
		} else if DetectGithubCi() {
			return GithubEnvironment()
		}
	}
	return LocalEnvironment()
}

func DetectInCi() bool {
	return os.Getenv("CI") != ""
}

func DetectGithubCi() bool {
	return os.Getenv("GITHUB_ACTIONS") != ""
}

func DetectGitlabCi() bool {
	return os.Getenv("GITLAB_CI") != ""
}
