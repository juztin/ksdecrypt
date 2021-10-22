package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"image/png"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/ssh/terminal"
)

func qrCode(s []byte) (*canvas.Image, error) {
	q, err := qr.Encode(hex.EncodeToString(s), qr.M, qr.Auto)
	if err == nil {
		q, err = barcode.Scale(q, 200, 200)
	}
	var b bytes.Buffer
	if err == nil {
		err = png.Encode(&b, q)
	}
	if err != nil {
		return nil, err
	}
	r := fyne.NewStaticResource("QR", b.Bytes())
	i := canvas.NewImageFromResource(r)
	i.FillMode = canvas.ImageFillOriginal
	return i, nil
}

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
	var (
		keystoreFlag string
		qrFlag       bool
	)
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to find home directory: %s\n", err)
		os.Exit(1)
	}
	flag.StringVar(&keystoreFlag, "keystore", filepath.Join(home, ".ethereum/keystore"), "Path to keystore")
	flag.BoolVar(&qrFlag, "qr", false, "Display the private key as a QR Code")
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
		a = common.HexToAddress(args[0])
		b, err = readKeystoreKey(keystoreFlag, a)
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
	pkey := crypto.FromECDSA(k)
	if qrFlag {
		img, err := qrCode(pkey)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		a := app.New()
		c := container.NewVBox(img, widget.NewLabel(crypto.PubkeyToAddress(k.PublicKey).Hex()))
		w := a.NewWindow("KSDecrypt")
		w.SetContent(c)
		w.CenterOnScreen()
		w.ShowAndRun()
	} else {
		fmt.Printf("Address:     %s\nPrivate Key: 0x%s\n", a, hexutil.Encode(pkey)[2:])
	}
}
