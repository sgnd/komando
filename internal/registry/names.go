package registry

import (
	"fmt"
	"regexp"
	"strings"
)

// The OCI distribution spec's grammar for names. komando checks a name
// before it goes into a URL path or a token scope, so "../" or a ":" in
// a name cannot reach another endpoint or ask for another scope.
var (
	repoRe = regexp.MustCompile(`^[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*$`)
	tagRe  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	refRe  = regexp.MustCompile(`^(sha256:[a-f0-9]{64}|sha512:[a-f0-9]{128})$`)
)

// CheckRepo says what is wrong with a repository name, or nil.
func CheckRepo(repo string) error {
	switch {
	case repo == "":
		return fmt.Errorf("the repository name is empty")
	case len(repo) > 255:
		return fmt.Errorf("the repository name %q is longer than 255 characters", repo)
	case strings.ToLower(repo) != repo && repoRe.MatchString(strings.ToLower(repo)):
		return fmt.Errorf("repository names are lower case: %s", strings.ToLower(repo))
	case !repoRe.MatchString(repo):
		return fmt.Errorf("%q is not a repository name (lower-case letters, digits, . _ - and / between parts, like shop/api)", repo)
	}
	return nil
}

// CheckRef says what is wrong with a tag or digest, or nil.
func CheckRef(ref string) error {
	if strings.Contains(ref, ":") {
		if !refRe.MatchString(ref) {
			return fmt.Errorf("%q is not a digest (sha256: and 64 hex digits)", ref)
		}
		return nil
	}
	if !tagRe.MatchString(ref) {
		return fmt.Errorf("%q is not a tag (letters, digits, . _ -, at most 128, not starting with . or -)", ref)
	}
	return nil
}

// DockerHub says whether the client talks to Docker Hub.
func (c *Client) DockerHub() bool { return c.Base.Host == "registry-1.docker.io" }

// Repo is the name the registry knows a repository by: on Docker Hub an
// official image (nginx) lives under library/, as docker pull reads it.
func (c *Client) Repo(repo string) string {
	if c.DockerHub() && !strings.Contains(repo, "/") {
		return "library/" + repo
	}
	return repo
}
