package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		secret     []byte
		passphrase []byte
	}{
		{
			name:       "random short",
			secret:     random(8),
			passphrase: random(8),
		},
		{
			name:       "random long",
			secret:     random(1024),
			passphrase: random(64),
		},
		{
			name:       "human",
			secret:     []byte("this is a great secret"),
			passphrase: []byte("this is a great passphrase"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testRun(t, test.secret, test.passphrase)
		})
	}
}
func testRun(t *testing.T, secret []byte, passphrase []byte) {
	file := path.Join(t.TempDir(), "secret.json")

	tio := testIO{
		secrets: [][]byte{secret},
		passphrases: [][]byte{
			passphrase,
			passphrase,
		},
	}
	err := run("encrypt", file, &tio)
	if err != nil {
		t.Fatal(err)
	}
	if len(tio.secrets) != 0 {
		t.Fatal("not all secrets consumed")
	}
	if len(tio.output) != 0 {
		t.Fatal("unexpected output")
	}

	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(b))

	tio = testIO{passphrases: [][]byte{passphrase}}
	err = run("decrypt", file, &tio)
	if err != nil {
		t.Fatal(err)
	}
	if len(tio.secrets) != 0 {
		t.Fatal("not all secrets consumed")
	}
	if !bytes.Equal(secret, tio.output) {
		t.Fatal("decrypted secret does not match input")
	}
}

type testIO struct {
	secrets     [][]byte
	passphrases [][]byte
	output      []byte
}

func (t *testIO) ReadSecret() ([]byte, error) {
	if len(t.secrets) == 0 {
		return nil, errors.New("no secrets")
	}

	secret := t.secrets[0]
	t.secrets = t.secrets[1:]

	return secret, nil
}

func (t *testIO) ReadPassphrase() ([]byte, error) {
	if len(t.passphrases) == 0 {
		return nil, errors.New("no secrets")
	}

	passphrase := t.passphrases[0]
	t.passphrases = t.passphrases[1:]

	return passphrase, nil
}

func (t *testIO) WriteSecret(bytes []byte) {
	t.output = bytes
}

func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)

	return b
}
