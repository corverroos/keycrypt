// Command bip39conv converts bytes (of any size) to a BIP39 mnemonic phrase and vice versa.
// It reads and writes to stdin and stdout. It is intended to be used in a pipeline.
// It pads the input to multiple of 32 bytes using --pad character (default is space).
// It trims the output of the mnemonic phrase using the same character.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/tyler-smith/go-bip39"
	"io"
	"os"
	"regexp"
	"strings"
)

var padding = flag.String("pad", " ", "padding character")

type inputoutput interface {
	ReadStdIn() ([]byte, error)
	WriteStdOut([]byte) error
}

type stdinout struct{}

func (stdinout) ReadStdIn() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}

func (stdinout) WriteStdOut(secret []byte) error {
	fmt.Print(string(secret))
	return nil
}

func main() {
	flag.Parse()
	if err := run(stdinout{}, rune((*padding)[0])); err != nil {
		fmt.Printf("Fatal error: %v\n", err)
		os.Exit(1)
	}
}

func run(inout inputoutput, pad rune) error {
	secret, err := inout.ReadStdIn()
	if err != nil {
		return err
	}

	if mnemonics, ok := getMnemonics(secret); ok {
		secret, err := fromMnemonic(mnemonics, pad)
		if err != nil {
			return fmt.Errorf("from mnemonic: %w", err)
		}

		err = inout.WriteStdOut(secret)
		if err != nil {
			return fmt.Errorf("write stdout: %w", err)
		}

		return nil
	}

	mnemonics, err := toMnemonic(secret, pad)
	if err != nil {
		return fmt.Errorf("to mnemonic: %w", err)
	}

	err = inout.WriteStdOut([]byte(strings.Join(mnemonics, " ")))
	if err != nil {
		return fmt.Errorf("write stdout: %w", err)
	}

	return nil
}

// getMnemonics returns true and converts the secret to an array of 24 word mnemonics if possible.
func getMnemonics(secret []byte) ([]string, bool) {
	split := bytes.Split(secret, []byte(" "))
	if len(split)%24 != 0 {
		return nil, false
	}

	var mnemonics []string
	for i := 0; i < len(split); i += 24 {
		words := split[i : i+24]
		for _, word := range words {
			match, err := regexp.Match(`[a-z]{3,10}`, word)
			if err != nil || !match {
				return nil, false
			}
		}
		mnemonic := string(bytes.Join(words, []byte(" ")))
		mnemonics = append(mnemonics, mnemonic)
	}

	return mnemonics, true
}

// fromMnemonic converts the array of 24 word mnemonics to a secret.
// It may be right-padded with spaces to a multiple of 32 bytes
// if toMnemonic was used to generate the mnemonic.
func fromMnemonic(mnemonic []string, padding rune) ([]byte, error) {
	var secret []byte
	for _, m := range mnemonic {
		decoded, err := bip39.EntropyFromMnemonic(m)
		if err != nil {
			return nil, fmt.Errorf("decode mnemonic: %w", err)
		}

		secret = append(secret, decoded...)
	}

	secret = bytes.TrimRight(secret, string(padding))

	return secret, nil
}

// toMnemonic converts the secret to a array of 24 word mnemonics.
// The secret is right-padded with spaces to a multiple of 32 bytes.
func toMnemonic(secret []byte, padding rune) ([]string, error) {
	mod := len(secret) % 32
	secret = pad(secret, 32-mod, padding)

	var resp []string
	for i := 0; i < len(secret)/32; i++ {
		next := secret[i*32 : (i+1)*32]

		mnomonic, err := bip39.NewMnemonic(next)
		if err != nil {
			return nil, fmt.Errorf("generate mnemonic: %w", err)
		}

		resp = append(resp, mnomonic)
	}

	return resp, nil
}

// pad right pads the secret with i padding bytes.
func pad(secret []byte, i int, padding rune) []byte {
	for j := 0; j < i; j++ {
		secret = append(secret, byte(padding))
	}

	return secret
}
