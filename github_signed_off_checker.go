package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"regexp"
	"strconv"
	"strings"

	"github.com/boltdb/bolt"
	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
)

const (
	DELIVERIES = "deliveries"
	SOC        = "signed-off-comments"
)

var (
	SUCCESS = "success"
	ERROR   = "error"
	context = "signed-off-by.me"
	dco     = "http://signed-off-by.me/"
	re      = regexp.MustCompile("Signed-off-by: (.* <.*>)")
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
	for _, k := range []string{DELIVERIES, SOC} {
		if _, err := b.CreateBucketIfNotExists([]byte(k)); err != nil {
			return err
		}
	}
	return nil
}

// Process verifies the signature and uniqueness of the delivery identifier.
func (GithubSignedOffChecker) Process(h Hook, r Request, b *bolt.Bucket) error {

	// Check uniqueness
	id := r.Headers["X-Github-Delivery"]
	if did := get(b, DELIVERIES, id); did != nil {
		return errors.New("duplicate delivery")
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
	var unsignedCommits []string
	var errs []error
	for _, c := range commits {
		if err := checkCommit(c); err != nil {
			unsignedCommits = append(unsignedCommits, *c.SHA)
			errs = append(errs, err)
		}
	}
	lastCommit := *commits[len(commits)-1].SHA
	if len(unsignedCommits) > 0 {

		var msg string
		msg = "All commits should be signed-off-by their respective authors"
		if _, _, err := client.Repositories.CreateStatus(owner, repo, lastCommit, &github.RepoStatus{
			State:       &ERROR,
			Context:     &context,
			TargetURL:   &dco,
			Description: &msg,
		}); err != nil {
			return fmt.Errorf("error status send: %v", err)
		}

		lastUnsignedCommit := unsignedCommits[len(unsignedCommits)-1]
		unsignedCommits := unsignedCommits[:len(unsignedCommits)-1]
		if len(unsignedCommits) > 0 {
			msg = fmt.Sprintf("Commits %s and %s are not signed-off.", strings.Join(unsignedCommits, ", "), lastUnsignedCommit)
		} else {
			msg = fmt.Sprintf("Commit %s is not signed-off.", lastUnsignedCommit)
		}
		cmnt := msg
		cmnt += "\n\nPlease fix these issues:\n\n"
		for i, err := range errs {
			cmnt += fmt.Sprintf(">\t%d. %v\n", i+1, err)
		}
		cmnt += "\n\nIf you'd like more information on how to sign your commits please visit [signed-off-by.me](https://signed-off-by.me)"

		if err := leaveComment(owner, repo, cmnt, number, client, b); err != nil {
			return err
		}
	} else {
		msg := fmt.Sprintf("All commits are signed-off.")
		if _, _, err := client.Repositories.CreateStatus(owner, repo, lastCommit, &github.RepoStatus{
			State:       &SUCCESS,
			Context:     &context,
			TargetURL:   &dco,
			Description: &msg,
		}); err != nil {
			return err
		}
		id := pullid(owner, repo, number)
		if commentID := get(b, SOC, id); commentID != nil {
			cid, err := strconv.Atoi(string(commentID))
			if err != nil {
				return err
			}
			if _, err = client.Issues.DeleteComment(owner, repo, cid); err != nil {
				return err
			} else {
				b.Delete([]byte(id))
			}
		}

	}

	return put(b, DELIVERIES, id, []byte{})
}
func leaveComment(owner, repo, body string, number int, client *github.Client, b *bolt.Bucket) error {
	id := pullid(owner, repo, number)
	commentID := get(b, SOC, id)
	newComment := func() error {
		c, _, err := client.Issues.CreateComment(owner, repo, number, &github.IssueComment{Body: &body})
		if err != nil {
			log.Println(err)
			return err
		}
		if err := put(b, SOC, id, []byte(strconv.Itoa(*c.ID))); err != nil {
			log.Fatal(err)
			return err
		}
		return nil
	}
	if commentID != nil {
		cid, err := strconv.Atoi(string(commentID))
		if err != nil {
			return err
		}
		_, _, err = client.Issues.EditComment(owner, repo, cid, &github.IssueComment{Body: &body})
		if err != nil {
			b.Delete([]byte(id))
			return newComment()
		}
		return err
	} else {
		return newComment()
	}
	return nil
}
func pullid(o, r string, n int) string {
	return fmt.Sprintf("%s-%s-%d", o, r, n)
}
func put(b *bolt.Bucket, bname, k string, v []byte) error {
	b = b.Bucket([]byte(bname))
	return b.Put([]byte(k), v)
}
func get(b *bolt.Bucket, bname, k string) []byte {
	b = b.Bucket([]byte(bname))
	if b == nil {
		log.Printf("bucket get: %s doesn't exist.\n", bname)
	}
	return b.Get([]byte(k))
}
func checkCommit(c *github.RepositoryCommit) error {
	x := re.FindStringSubmatch(*c.Commit.Message)
	if len(x) == 2 {
		addr, err := mail.ParseAddress(x[1])
		if err != nil {
			return fmt.Errorf("%s has a malformed signature.", *c.Commit.Author.Name, (*c.SHA)[:7])
		}
		if *c.Commit.Author.Name != addr.Name {
			return fmt.Errorf("Commit author name and signed-off-by author don't match.")
		}
		if *c.Commit.Author.Email != addr.Address {
			return fmt.Errorf("Commit author email and signed-off-by address do not match.")
		}
		return nil
	} else {
		return fmt.Errorf("%s has not signed-off %s.", *c.Commit.Author.Name, (*c.SHA)[:7])
	}
}
