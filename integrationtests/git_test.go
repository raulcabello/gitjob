package integrationtests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pkg/errors"
	"github.com/rancher/gitjob/e2e/githelper"
	gitjobv1 "github.com/rancher/gitjob/pkg/apis/gitjob.cattle.io/v1"
	"github.com/rancher/gitjob/pkg/git"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"
	v1 "k8s.io/api/core/v1"
	"os"
	"path"
	"strings"
	"testing"
	"time"
)

func TestLatestCommit(t *testing.T) {
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "nginx-git:test1", //TODO change!
		ExposedPorts: []string{"8080/tcp"},
		WaitingFor:   wait.ForLog("spawn-fcgi: child spawned successfully"),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Error(err)
	}
	repoUrl, err := getRepoUrl(ctx, container)
	if err != nil {
		t.Error(err.Error())
	}
	defer func() {
		if err := container.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate container: %s", err.Error())
		}
	}()

	time.Sleep(1 * time.Second) //TODO remove

	initialCommit, err := createRepoWithInitialCommit(repoUrl)
	if err != nil {
		t.Error(err.Error())
	}

	gitjob := &gitjobv1.GitJob{
		Spec: gitjobv1.GitJobSpec{
			Git: gitjobv1.GitInfo{
				Repo:   repoUrl,
				Branch: "master",
			},
		},
	}
	secret := &v1.Secret{
		Data: map[string][]byte{v1.BasicAuthUsernameKey: []byte("fleet-ci"), v1.BasicAuthPasswordKey: []byte("pass")},
		Type: v1.SecretTypeBasicAuth,
	}

	commit, err := git.LatestCommit(gitjob, &secretGetter{secret})

	if err != nil {
		t.Error(err.Error())
	}
	if initialCommit != commit {
		t.Errorf("initial commit %s and commit %s don't match", initialCommit, commit)
	}
}

func TestLatestCommitSSH(t *testing.T) {
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "nginx-git:test", //TODO change!
		ExposedPorts: []string{"8080/tcp"},
		WaitingFor:   wait.ForLog("spawn-fcgi: child spawned successfully"),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Error(err)
	}
	repoUrl, err := getRepoUrl(ctx, container)
	if err != nil {
		t.Error(err.Error())
	}
	defer func() {
		if err := container.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate container: %s", err.Error())
		}
	}()

	time.Sleep(1 * time.Second) //TODO remove
	publicKey, privateKey, err := makeSSHKeyPair()
	if err != nil {
		t.Error(err.Error())
	}
	err = container.CopyToContainer(ctx, []byte(publicKey), "/tes2t", 700)
	if err != nil {
		t.Error(err.Error())
	}

	initialCommit, err := createRepoWithInitialCommit(repoUrl)
	if err != nil {
		t.Error(err.Error())
	}

	gitjob := &gitjobv1.GitJob{
		Spec: gitjobv1.GitJobSpec{
			Git: gitjobv1.GitInfo{
				Repo:   repoUrl,
				Branch: "master",
			},
		},
	}
	secret := &v1.Secret{
		Data: map[string][]byte{v1.BasicAuthUsernameKey: []byte("fleet-ci"), v1.BasicAuthPasswordKey: []byte("pass")},
		Type: v1.SecretTypeBasicAuth,
	}

	commit, err := git.LatestCommit(gitjob, &secretGetter{secret})

	if err != nil {
		t.Error(err.Error())
	}
	if initialCommit != commit {
		t.Errorf("initial commit %s and commit %s don't match", initialCommit, commit)
	}
}

func getRepoUrl(ctx context.Context, container testcontainers.Container) (string, error) {
	mappedPort, err := container.MappedPort(ctx, "8080")
	if err != nil {
		return "", err
	}
	host, err := container.Host(ctx)
	if err != nil {
		return "", err
	}
	repoUrl := "http://" + host + ":" + mappedPort.Port() + "/repo"

	return repoUrl, nil
}

func createRepoWithInitialCommit(url string) (string, error) {
	err := os.Setenv("GIT_HTTP_USER", "fleet-ci")
	if err != nil {
		return "", err
	}
	err = os.Setenv("GIT_HTTP_PASSWORD", "pass")
	if err != nil {
		return "", err
	}
	g := githelper.NewHTTP(url)
	tmpdir, _ := os.MkdirTemp("", "fleet-")
	repodir := path.Join(tmpdir, "repo")
	c, err := g.Create(repodir, "gitrepo", "examples")
	if err != nil {
		return "", err
	}
	log, err := c.Log(&gogit.LogOptions{})
	if err != nil {
		return "", err
	}

	numCommits := 0
	commitHash := ""
	err = log.ForEach(func(commit *object.Commit) error {
		commitHash = commit.Hash.String()
		numCommits++

		return nil
	})

	if numCommits != 1 {
		return "", errors.Errorf("It should be just one commit, found %d commits", numCommits)
	}
	if err != nil {
		return "", err
	}

	return commitHash, nil
}

type secretGetter struct {
	secret *v1.Secret
}

func (s *secretGetter) Get(string, string) (*v1.Secret, error) {
	return s.secret, nil
}

func makeSSHKeyPair() (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return "", "", err
	}

	// generate and write private key as PEM
	var privKeyBuf strings.Builder

	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(&privKeyBuf, privateKeyPEM); err != nil {
		return "", "", err
	}

	// generate and write public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	var pubKeyBuf strings.Builder
	pubKeyBuf.Write(ssh.MarshalAuthorizedKey(pub))

	return pubKeyBuf.String(), privKeyBuf.String(), nil
}
