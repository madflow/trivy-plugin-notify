package environment

import (
	"fmt"
	"os"
)

func GithubEnvironment() EnvironmentCi {
	return EnvironmentCi{
		Provider: "github",
		Project:  os.Getenv("GITHUB_REPOSITORY"),
		Ref:      os.Getenv("GITHUB_REF_NAME"),
		Url:      fmt.Sprintf("%s/%s", os.Getenv("GITHUB_SERVER_URL"), os.Getenv("GITHUB_REPOSITORY")),
	}
}
