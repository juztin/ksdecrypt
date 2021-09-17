Simple Ethereum keystore decryption util.

#### Build

```
go build .
```

#### Install

```
go install github.com/juztin/ksdecrypt@latest
```

#### Usage

Decrypt the key for address `0x4565c9288F44F260636789BAd2E7aB973b247C28`, from within `$HOME/.ethereum/keystore`:

```
ksdecrypt 0x4565c9288F44F260636789BAd2E7aB973b247C28
```

Decrypt the keystore file: `secret.key`

```
ksdecrypt -keystore secret.key
```
