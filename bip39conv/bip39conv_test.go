package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestRun(t *testing.T) {
	for i := 0; i < 100; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			b := random(i * 17)

			pad := ' '
			if bytes.HasSuffix(b, []byte{byte(pad)}) {
				t.Skip("already padded")
			}

			inout := &testIO{input: b}
			err := run(inout, pad)
			if err != nil {
				t.Fatal(err)
			}

			input2 := &testIO{input: inout.output}
			err = run(input2, pad)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(b, input2.output) {
				t.Fatal("not equal")
			}
		})
	}
}

func TestToMnemonic(t *testing.T) {
	for _, i := range []int{1, 32, 64, 144, 1024, 1034, 2047, 2048, 2049} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			b := random(i)
			pad := ' '
			if bytes.HasSuffix(b, []byte{byte(pad)}) {
				t.Skip("already padded")
			}

			mnemonic, err := toMnemonic(b, pad)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("i=%d, len=%d, mnemonic=%v\n", i, len(mnemonic), mnemonic)

			secret, err := fromMnemonic(mnemonic, pad)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(b, secret) {
				t.Fatal("not equal")
			}
		})
	}
}

func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)

	return b
}

type testIO struct {
	input  []byte
	output []byte
}

func (t *testIO) ReadStdIn() ([]byte, error) {
	return t.input, nil
}

func (t *testIO) WriteStdOut(bytes []byte) error {
	t.output = bytes
	return nil
}
