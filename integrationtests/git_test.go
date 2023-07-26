package integrationtests

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	cp "github.com/otiai10/copy"
	"github.com/pkg/errors"
	"github.com/rancher/gitjob/e2e/githelper"
	gitjobv1 "github.com/rancher/gitjob/pkg/apis/gitjob.cattle.io/v1"
	"github.com/rancher/gitjob/pkg/git"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"
	"io"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/json"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"
)

const (
	latestCommitPublicRepo  = "8cd5ab9c851482ce13a544c91ee010f6fdc7cf3f"
	latestCommitPrivateRepo = "417310891d63d3f3a478bd4c5013e2f532056e8e"
)

/*
These tests
*/

func TestLatestCommit_NoAuth(t *testing.T) {
	ctx := context.Background()
	container, url, err := createGogsContainer(ctx, createTempFolder(t))
	if err != nil {
		t.Errorf("got error when none was expected: %v", err)
	}
	defer func() {
		if err := container.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate container: %s", err.Error())
		}
	}()

	tests := map[string]struct {
		gitjob         *gitjobv1.GitJob
		expectedCommit string
		expectedErr    error
	}{
		"public repo": {
			gitjob: &gitjobv1.GitJob{
				Spec: gitjobv1.GitJobSpec{
					Git: gitjobv1.GitInfo{
						Repo:   url + "/test/public-repo",
						Branch: "master",
					},
				},
			},
			expectedCommit: latestCommitPublicRepo,
			expectedErr:    nil,
		},
		"private repo": {
			gitjob: &gitjobv1.GitJob{
				Spec: gitjobv1.GitJobSpec{
					Git: gitjobv1.GitInfo{
						Repo:   url + "/test/private-repo",
						Branch: "master",
					},
				},
			},
			expectedCommit: "",
			expectedErr:    transport.ErrAuthenticationRequired,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			secretGetter := &secretGetterMock{err: kerrors.NewNotFound(schema.GroupResource{}, "notfound")}
			latestCommit, err := git.LatestCommit(test.gitjob, secretGetter)
			if err != test.expectedErr {
				t.Errorf("expecter error is: %v, but got %v", test.expectedErr, err)
			}
			if latestCommit != test.expectedCommit {
				t.Errorf("latestCommit doesn't match. got %s, expected %s", latestCommit, test.expectedCommit)
			}
		})
	}

}

func TestLatestCommit_BasicAuth(t *testing.T) {
	ctx := context.Background()
	container, url, err := createGogsContainer(ctx, createTempFolder(t))
	if err != nil {
		t.Errorf("got error when none was expected: %v", err)
	}
	defer func() {
		if err := container.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate container: %s", err.Error())
		}
	}()

	tests := map[string]struct {
		gitjob         *gitjobv1.GitJob
		expectedCommit string
		expectedErr    error
	}{
		"public repo": {
			gitjob: &gitjobv1.GitJob{
				Spec: gitjobv1.GitJobSpec{
					Git: gitjobv1.GitInfo{
						Repo:   url + "/test/public-repo",
						Branch: "master",
					},
				},
			},
			expectedCommit: latestCommitPublicRepo,
			expectedErr:    nil,
		},
		"private repo": {
			gitjob: &gitjobv1.GitJob{
				Spec: gitjobv1.GitJobSpec{
					Git: gitjobv1.GitInfo{
						Repo:   url + "/test/private-repo",
						Branch: "master",
					},
				},
			},
			expectedCommit: latestCommitPrivateRepo,
			expectedErr:    nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			secret := &v1.Secret{
				Data: map[string][]byte{v1.BasicAuthUsernameKey: []byte("test"), v1.BasicAuthPasswordKey: []byte("pass")}, //TODO const
				Type: v1.SecretTypeBasicAuth,
			}
			secretGetter := &secretGetterMock{secret: secret}
			latestCommit, err := git.LatestCommit(test.gitjob, secretGetter)
			if err != test.expectedErr {
				t.Errorf("expecter error is: %v, but got %v", test.expectedErr, err)
			}
			if latestCommit != test.expectedCommit {
				t.Errorf("latestCommit doesn't match. got %s, expected %s", latestCommit, test.expectedCommit)
			}
		})
	}
}

func TestLatestCommitSSH(t *testing.T) {
	ctx := context.Background()
	container, url, err := createGogsContainer(ctx, createTempFolder(t))
	if err != nil {
		t.Errorf("got error when none was expected: %v", err)
	}
	defer func() {
		if err := container.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate container: %s", err.Error())
		}
	}()
	publicKey, privateKey, err := makeSSHKeyPair()
	err = addPublicKey(url, publicKey)
	if err != nil {
		t.Errorf("got error when none was expected: %v", err)
	}
	mappedPort, err := container.MappedPort(ctx, "22")
	if err != nil {
		t.Errorf("got error when none was expected: %v", err)
	}

	sshUrl := "ssh://git@localhost:" + mappedPort.Port() + "/test/"
	tests := map[string]struct {
		gitjob         *gitjobv1.GitJob
		expectedCommit string
		expectedErr    error
	}{
		"public repo": {
			gitjob: &gitjobv1.GitJob{
				Spec: gitjobv1.GitJobSpec{
					Git: gitjobv1.GitInfo{
						Repo:   sshUrl + "public-repo",
						Branch: "master",
					},
				},
			},
			expectedCommit: latestCommitPublicRepo,
			expectedErr:    nil,
		},
		"private repo": {
			gitjob: &gitjobv1.GitJob{
				Spec: gitjobv1.GitJobSpec{
					Git: gitjobv1.GitInfo{
						Repo:   sshUrl + "private-repo", //git@localhost:test/private-repo.git
						Branch: "master",
					},
				},
			},
			expectedCommit: latestCommitPrivateRepo,
			expectedErr:    nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			secret := &v1.Secret{
				Data: map[string][]byte{
					v1.SSHAuthPrivateKey: []byte(privateKey),
					"known_hosts":        []byte("localhost " + publicKey),
				},
				Type: v1.SecretTypeSSHAuth,
			}
			secretGetter := &secretGetterMock{secret: secret}
			latestCommit, err := git.LatestCommit(test.gitjob, secretGetter)
			if err != test.expectedErr {
				t.Errorf("expecter error is: %v, but got %v", test.expectedErr, err)
			}
			if latestCommit != test.expectedCommit {
				t.Errorf("latestCommit doesn't match. got %s, expected %s", latestCommit, test.expectedCommit)
			}
		})
	}
}

func createGogsContainer(ctx context.Context, tmpDir string) (testcontainers.Container, string, error) {
	err := cp.Copy("./assets/gitserver", tmpDir)
	if err != nil {
		return nil, "", err
	}
	req := testcontainers.ContainerRequest{
		Image:        "gogs/gogs:0.13", //TODO change!
		ExposedPorts: []string{"3000/tcp", "22/tcp"},
		WaitingFor:   wait.ForHTTP("/").WithPort("3000/tcp"),
		Mounts: testcontainers.ContainerMounts{
			{
				Source: testcontainers.GenericBindMountSource{HostPath: tmpDir},
				Target: "/data",
			},
		},
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})

	if err != nil {
		return nil, "", err
	}

	url, err := getUrl(ctx, container)
	if err != nil {
		return nil, "", err
	}

	return container, url, nil
}

func getUrl(ctx context.Context, container testcontainers.Container) (string, error) {
	mappedPort, err := container.MappedPort(ctx, "3000")
	if err != nil {
		return "", err
	}
	host, err := container.Host(ctx)
	if err != nil {
		return "", err
	}
	url := "http://" + host + ":" + mappedPort.Port()

	return url, nil
}

func addPublicKey(url string, publicKey string) error {
	token, err := createGogsToken(url)
	if err != nil {
		return err
	}
	fmt.Println(token)
	//Authorization: token
	publicKeyUrl := url + "/api/v1/user/keys"
	values := map[string]string{"title": "testKey", "key": publicKey}
	jsonValue, _ := json.Marshal(values)
	client := &http.Client{}

	req, err := http.NewRequest(http.MethodPost, publicKeyUrl, bytes.NewBuffer(jsonValue))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "token "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return errors.New(string(body))
	}

	return nil
}

func createGogsToken(url string) (string, error) {
	tokenUrl := url + "/api/v1/users/test/tokens"
	values := map[string]string{"name": "token"}
	jsonValue, _ := json.Marshal(values)
	client := &http.Client{}

	req, err := http.NewRequest(http.MethodPost, tokenUrl, bytes.NewBuffer(jsonValue))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("test", "pass") //move to const
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	tokenResponse := &tokenResponse{}
	err = json.Unmarshal(body, tokenResponse)
	if err != nil {
		return "", err
	}

	return tokenResponse.Sha1, nil
}

type tokenResponse struct {
	Name string `json:"name,omitempty"`
	Sha1 string `json:"sha1,omitempty"`
}

// explain cannot clean up in gh actions
func createTempFolder(t *testing.T) string {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		tmp, err := os.MkdirTemp("", "gogs")
		if err != nil {
			t.Errorf("got error when none was expected: %v", err)
		}
		return tmp
	}

	return t.TempDir()
}

func createRepoWithInitialCommit(url string) (string, error) {
	/*err := os.Setenv("GIT_HTTP_USER", "fleet-ci")
	if err != nil {
		return "", err
	}
	err = os.Setenv("GIT_HTTP_PASSWORD", "pass")
	if err != nil {
		return "", err
	}*/
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

type secretGetterMock struct {
	secret *v1.Secret
	err    error
}

func (s *secretGetterMock) Get(string, string) (*v1.Secret, error) {
	if s.err != nil {
		return nil, s.err
	}
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
