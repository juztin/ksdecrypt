package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/ssh/terminal"
)

func readKey(path string, fi fs.FileInfo) (string, []byte, error) {
	f, err := os.Open(filepath.Join(path, fi.Name()))
	if err != nil {
		return "", nil, err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return "", nil, err
	}
	a := struct{ Address string }{}
	return a.Address, b, json.Unmarshal(b, &a)
}

func readKeystoreKey(keystorePath string, addr common.Address) ([]byte, error) {
	fileInfo, err := ioutil.ReadDir(keystorePath)
	if err != nil {
		return nil, err
	}
	for _, f := range fileInfo {
		switch mode := f.Mode(); {
		case mode.IsDir() || !mode.IsRegular():
			continue
		}
		a, b, err := readKey(keystorePath, f)
		if err == nil && common.HexToAddress(a) == addr {
			return b, nil
		}
	}
	return nil, errors.New("address not found")
}

func decryptKey(keystorePath string, addr common.Address) (*ecdsa.PrivateKey, error) {
	s, err := os.Stat(keystorePath)
	if err != nil {
		return nil, err
	}
	var b []byte
	if s.IsDir() {
		b, err = readKeystoreKey(keystorePath, addr)
		if err != nil {
			return nil, err
		}
	} else {
	}
	fmt.Printf("Password for %s: ", addr)
	passphrase, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	k, err := keystore.DecryptKey(b, string(passphrase))
	if err != nil {
		return nil, err
	}
	return k.PrivateKey, nil
}

func main() {
	var keystoreFlag string
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to find home directory: %w\n", err)
		os.Exit(1)
	}
	flag.StringVar(&keystoreFlag, "keystore", filepath.Join(home, ".ethereum/keystore"), "Path to keystore")
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "Received %d args but expected %d\n", len(args), 1)
		flag.Usage()
		os.Exit(1)
	}
	if common.IsHexAddress(args[0]) == false {
		fmt.Fprintln(os.Stderr, "Invalid address")
		flag.Usage()
		os.Exit(1)
	}
	k, err := decryptKey(keystoreFlag, common.HexToAddress(args[0]))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get key: %w\n", err)
		os.Exit(1)
	}
	fmt.Println(hexutil.Encode(crypto.FromECDSA(k))[2:])
}
