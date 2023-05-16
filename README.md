# keycrypt

Keycrypt is a simple tool to encrypt and decrypt secrets using a passphrase. 
It uses Ethereum wallet style encryption. 

## Usage

Install:
```sh
go install github.com/corverroos/keycrypt
```

Encrypt:
```sh
keycrypt -cmd=encrypt -file=path/to/encrypted.json 
# Enter secret
# Enter passphrase twice
```

Decrypt:
```sh
keycrypt -cmd=decrypt -file=path/to/encrypted.json
# Enter passphrase
```