package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"regexp"

	"golang.org/x/oauth2"

	"github.com/boltdb/bolt"
	"github.com/google/go-github/github"
)

var (
	SUCCESS = "success"
	ERROR   = "error"
	context = "sevki.io/dco"
	dco     = "http://developercertificate.org/"
)

func init() {
	RegisterComponent("github-signed-off-checker", GithubSignedOffChecker{})
}

// GithubValidator checks if the signature for an incoming request matches the
// calculated HMAC of the request body. It also checks if the unique identifier
// hasn't been processed before to prevent replay attacks.
type GithubSignedOffChecker struct{}

// Name returns the name of this component.
func (GithubSignedOffChecker) Name() string { return "Github Signed Off Checker" }

// Template returns the HTML template name of this component.
func (GithubSignedOffChecker) Template() string { return "github-signed-off-checker" }

// Params returns the currently stored configuration parameters for hook h
// from bucket b.
func (GithubSignedOffChecker) Params(h Hook, b *bolt.Bucket) map[string]string {
	m := make(map[string]string)
	for _, k := range []string{"token"} {
		m[k] = string(b.Get([]byte(fmt.Sprintf("%s-%s", h.ID, k))))
	}
	return m
}

// Init initializes this component. It requires a token to be present.
func (GithubSignedOffChecker) Init(h Hook, params map[string]string, b *bolt.Bucket) error {
	token, ok := params["token"]
	if !ok {
		return errors.New("token is required")
	}
	if err := b.Put([]byte(fmt.Sprintf("%s-token", h.ID)), []byte(token)); err != nil {
		return err
	}
	_, err := b.CreateBucketIfNotExists([]byte("deliveries"))
	return err
}

// Process verifies the signature and uniqueness of the delivery identifier.
func (GithubSignedOffChecker) Process(h Hook, r Request, b *bolt.Bucket) error {
	re := regexp.MustCompile("Signed-off-by: (.* <.*>)")

	token := b.Get([]byte(fmt.Sprintf("%s-token", h.ID)))
	if token == nil {
		return errors.New("github validator not initialized")
	}

	var pr github.PullRequestEvent
	if err := json.Unmarshal(r.Body, &pr); err != nil {
		return err
	}
	if pr.PullRequest == nil {
		return errors.New("not a PR")
	}

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: string(token)},
	)
	tc := oauth2.NewClient(oauth2.NoContext, ts)

	client := github.NewClient(tc)

	owner := *pr.PullRequest.Base.Repo.Owner.Login
	repo := *pr.PullRequest.Base.Repo.Name
	commits, _, err := client.PullRequests.ListCommits(owner, repo, *pr.Number, &github.ListOptions{})
	if err != nil {
		return err
	}
	for _, c := range commits {
		x := re.FindStringSubmatch(*c.Commit.Message)
		if len(x) == 2 {
			addr, err := mail.ParseAddress(x[1])
			if err != nil {
				return err
			}
			if *c.Commit.Author.Name != addr.Name {
				msg := fmt.Sprintf("Commit author and signed-off-by author don't match.")
				if _, _, err := client.Repositories.CreateStatus(owner, repo, *c.SHA, &github.RepoStatus{
					State:       &ERROR,
					Context:     &context,
					TargetURL:   &dco,
					Description: &msg,
				}); err != nil {
					return err
				}
			}
			if *c.Commit.Author.Email != addr.Address {
				msg := fmt.Sprintf("Commit address and signed-off-by address do not match.")
				if _, _, err := client.Repositories.CreateStatus(owner, repo, *c.SHA, &github.RepoStatus{
					State:       &ERROR,
					Context:     &context,
					TargetURL:   &dco,
					Description: &msg,
				}); err != nil {
					return err
				}
			}
			log.Printf("%s\n", addr)
		} else {
			msg := fmt.Sprintf("Commit %s is not signed-off", (*c.SHA)[:7])
			if _, _, err := client.Repositories.CreateStatus(owner, repo, *c.SHA, &github.RepoStatus{
				State:       &ERROR,
				Context:     &context,
				TargetURL:   &dco,
				Description: &msg,
			}); err != nil {
				return err
			}

		}
	}
	// Check uniqueness
	id := []byte(r.Headers["X-Github-Delivery"])
	deliveries := b.Bucket([]byte("deliveries"))
	if did := deliveries.Get([]byte(id)); did != nil {
		return errors.New("duplicate delivery")
	}
	return deliveries.Put([]byte(id), []byte{})
}
