package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/ssh/terminal"
)

func readKey(path string) (common.Address, []byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return common.Address{}, nil, err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return common.Address{}, b, err
	}
	a := struct{ Address string }{}
	err = json.Unmarshal(b, &a)
	if err != nil {
		return common.Address{}, b, err
	}
	return common.HexToAddress(a.Address), b, nil
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
		a, b, err := readKey(filepath.Join(keystorePath, f.Name()))
		//if err == nil && common.HexToAddress(a) == addr {
		if err == nil && a == addr {
			return b, nil
		}
	}
	return nil, errors.New("address not found")
}

func decryptKey(key []byte) (*ecdsa.PrivateKey, error) {
	fmt.Printf("Password: ")
	passphrase, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	k, err := keystore.DecryptKey(key, string(passphrase))
	if err != nil {
		return nil, err
	}
	return k.PrivateKey, nil
}

func main() {
	var keystoreFlag string
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to find home directory: %s\n", err)
		os.Exit(1)
	}
	flag.StringVar(&keystoreFlag, "keystore", filepath.Join(home, ".ethereum/keystore"), "Path to keystore")
	flag.Parse()
	args := flag.Args()

	s, err := os.Stat(keystoreFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read 'keystore' path: %s\n", err)
		os.Exit(1)
	}
	var b []byte
	var a common.Address
	if s.IsDir() {
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
		b, err = readKeystoreKey(keystoreFlag, common.HexToAddress(args[0]))
	} else {
		a, b, err = readKey(keystoreFlag)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed read key: %s\n", err)
		os.Exit(1)
	}
	k, err := decryptKey(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decrypt key: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Address:     %s\nPrivate Key: 0x%s\n", a, hexutil.Encode(crypto.FromECDSA(k))[2:])
}
