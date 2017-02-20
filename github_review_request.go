package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/boltdb/bolt"
	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
)

var (
	reviewRegex = regexp.MustCompile("R=([[:alnum:]]*)")
)

func init() {
	RegisterComponent("github-review-request", GithubReviewRequest{})
}

type GithubReviewRequest struct{}

// Name returns the name of this component.
func (GithubReviewRequest) Name() string { return "Github Review Request" }

// Template returns the HTML template name of this component.
func (GithubReviewRequest) Template() string { return "github-review-request" }

// Params returns the currently stored configuration parameters for hook h
// from bucket b.
func (GithubReviewRequest) Params(h Hook, b *bolt.Bucket) map[string]string {
	m := make(map[string]string)
	for _, k := range []string{"token"} {
		m[k] = string(b.Get([]byte(fmt.Sprintf("%s-%s", h.ID, k))))
	}
	return m
}

// Init initializes this component. It requires a token to be present.
func (GithubReviewRequest) Init(h Hook, params map[string]string, b *bolt.Bucket) error {
	token, ok := params["token"]
	if !ok {
		return errors.New("token is required")
	}
	if err := b.Put([]byte(fmt.Sprintf("%s-token", h.ID)), []byte(token)); err != nil {
		return err
	}
	for _, k := range []string{DELIVERIES} {
		if _, err := b.CreateBucketIfNotExists([]byte(k)); err != nil {
			return err
		}
	}
	return nil
}

// Process verifies the signature and uniqueness of the delivery identifier.
func (GithubReviewRequest) Process(h Hook, r Request, b *bolt.Bucket) error {

	// Check uniqueness
	id := fmt.Sprintf("GHR-%s", r.Headers["X-Github-Delivery"])
	if did := get(b, DELIVERIES, id); did != nil {
		//		return errors.New("duplicate delivery")
	}
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
	number := *pr.Number
	commits, _, err := client.PullRequests.ListCommits(owner, repo, *pr.Number, &github.ListOptions{})
	if err != nil {
		return err
	}
	var reviewers []string

	for _, c := range commits {
		x := reviewRegex.FindAllStringSubmatch(*c.Commit.Message, -1)
		for _, match := range x {
			reviewers = append(reviewers, match[1])
		}
	}
	reviewersReq := &github.PullRequestReviewerRequest{reviewers}
	_, _, err = client.PullRequests.RequestReviewers(owner, repo, number, reviewersReq)
	if err != nil {
		return err
	}
	return put(b, DELIVERIES, id, []byte{})
}
