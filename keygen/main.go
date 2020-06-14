package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
)

type keystoreFile struct {
	PrivateKey string `json:"privateKey"`
	ID         string `json:"ID"`
}

func main() {
	priv, _, err := crypto.GenerateKeyPair(
		crypto.Ed25519, // Select your key type. Ed25519 are nice short
		-1,             // Select key length when possible (i.e. RSA).
	)
	if err != nil {
		panic(err)
	}

	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		panic(err)
	}

	privBytes, err := priv.Bytes()
	if err != nil {
		panic(err)
	}
	privStr := hex.EncodeToString(privBytes)

	keystore := keystoreFile{PrivateKey: privStr, ID: id.String()}

	buf, err := json.Marshal(keystore)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(buf))
}
