// Command keycrypt encrypts and decrypts secrets using the Ethereum 2.0 wallet keystorev4 format.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/nbutton23/zxcvbn-go"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	"golang.org/x/term"
	"os"
	"strings"
	"syscall"
)

var (
	cmd  = flag.String("cmd", "", "command to run: encrypt or decrypt")
	file = flag.String("file", "", "file to encrypt or decrypt")
)

type inputoutput interface {
	ReadSecret() ([]byte, error)
	ReadPassphrase() ([]byte, error)
	WriteSecret([]byte)
}

type stdinout struct{}

func (stdinout) ReadPassphrase() ([]byte, error) {
	return readPassphrase()
}

func (stdinout) ReadSecret() ([]byte, error) {
	return readSecret()
}

func (stdinout) WriteSecret(secret []byte) {
	fmt.Println(string(secret))
}

func main() {
	flag.Parse()
	if err := run(*cmd, *file, stdinout{}); err != nil {
		fmt.Printf("Fatal error: %v\n", err)
		os.Exit(1)
	}
}

func run(cmd string, file string, inputoutput inputoutput) error {
	if file == "" {
		return fmt.Errorf("--file not specified")
	}

	switch cmd {
	case "encrypt":
		err := encrypt(file, inputoutput)
		if err != nil {
			return fmt.Errorf("encrypt error: %w", err)
		}
	case "decrypt":
		err := decrypt(file, inputoutput)
		if err != nil {
			return fmt.Errorf("decrypt error: %w", err)
		}
	default:
		return fmt.Errorf("unknown --cmd %q", cmd)
	}

	return nil
}

func encrypt(output string, inputoutput inputoutput) error {
	if _, err := os.Stat(output); err == nil {
		return fmt.Errorf("file %s already exists", output)
	}

	fmt.Print("Enter secret to encrypt: ")
	secret, err := inputoutput.ReadSecret()
	if err != nil {
		return err
	}

	fmt.Print("Enter encryption passphrase: ")
	passphrase, err := inputoutput.ReadPassphrase()
	if err != nil {
		return err
	}

	strength := zxcvbn.PasswordStrength(string(passphrase), nil)
	fmt.Printf("\nPassword strength=%d/5, crack_time=%s", strength.Score+1, strength.CrackTimeDisplay)

	fmt.Print("\nEnter passphrase again: ")
	passphrase2, err := inputoutput.ReadPassphrase()
	if err != nil {
		return err
	}

	if !bytes.Equal(passphrase, passphrase2) {
		return fmt.Errorf("passphrases do not match")
	}

	fmt.Printf("\nSecret length: %d, passphrase length: %d\n",
		len(string(secret)), len(string(passphrase)))

	encryptor := keystorev4.New(keystorev4.WithCipher("scrypt"))
	encrypted, err := encryptor.Encrypt(secret, string(passphrase))
	if err != nil {
		return err
	}

	b, err := json.MarshalIndent(encrypted, "", " ")
	if err != nil {
		return fmt.Errorf("read secret: %w", err)
	}

	if !strings.Contains(output, ".json") {
		output = output + ".json"
	}

	fmt.Printf("Writing encrypted secret to %s\n", output)

	if err = os.WriteFile(output, b, 0400); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

func decrypt(input string, inputoutput inputoutput) error {
	fmt.Print("Enter encryption passphrase: ")
	passphrase, err := inputoutput.ReadPassphrase()
	if err != nil {
		return err
	}

	fmt.Printf("\nPassphrase length: %d\n", len(string(passphrase)))

	b, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	fields := make(map[string]interface{})
	if err := json.Unmarshal(b, &fields); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	encryptor := keystorev4.New(keystorev4.WithCipher("scrypt"))
	decrypted, err := encryptor.Decrypt(fields, string(passphrase))
	if err != nil {
		return err
	}

	fmt.Printf("Decrypted secret:\n")
	inputoutput.WriteSecret(decrypted)

	return nil
}

func readSecret() ([]byte, error) {
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("read secret: %w", err)
	}

	return bytes.TrimSpace(input), nil
}
func readPassphrase() ([]byte, error) {
	b, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return nil, fmt.Errorf("read secret: %w", err)
	}

	return bytes.TrimSpace(b), nil
}
