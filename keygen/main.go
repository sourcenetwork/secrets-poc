package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/libp2p/go-libp2p-core/crypto"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

type keystoreFile struct {
	PrivateKey string `json:"privateKey"`
	ID         string `json:"ID"`
}

func publicKeyToEdwards25519KyberPoint(pubkey []byte) kyber.Point {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	point := suite.Point()
	point.UnmarshalBinary(pubkey)
	return point
}

func privateKeyToEdwards25519KyberPoint(priv []byte) kyber.Scalar {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	scalar := suite.Scalar()
	scalar.UnmarshalBinary(priv)
	return scalar
}

func main() {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	rand := suite.RandomStream()
	privTemp := suite.Scalar().Pick(rand)       // create a private key x
	pubTemp := suite.Point().Mul(privTemp, nil) // public key
	b, _ := privTemp.MarshalBinary()
	buf := bytes.NewBuffer(b)
	priv, pub, err := crypto.GenerateEd25519Key(buf)
	if err != nil {
		panic(err)
	}

	fmt.Println("Private:")
	privCBytes, err := priv.Raw()
	if err != nil {
		panic(err)
	}
	fmt.Println("P2P:", hex.EncodeToString(privCBytes))

	privKBytes, err := privTemp.MarshalBinary()
	if err != nil {
		panic(err)
	}
	fmt.Println("Kyber:", hex.EncodeToString(privKBytes))

	fmt.Println("\nPublic:")
	pubCBytes, err := pub.Raw()
	if err != nil {
		panic(err)
	}
	fmt.Println("P2P:", hex.EncodeToString(pubCBytes))

	pubKBytes, err := pubTemp.MarshalBinary()
	if err != nil {
		panic(err)
	}
	fmt.Println("Kyber1:", pubTemp.String())
	fmt.Println("Kyber2:", hex.EncodeToString(pubKBytes))

	// pubBytes1, _ := pub.Raw()
	// fmt.Println(publicKeyToEdwards25519KyberPoint(pubBytes1).String())
	// fmt.Println(pubTemp.String())
	// fmt.Println("--")

	// // priv, _, err := crypto.GenerateKeyPair(
	// // 	crypto.Ed25519, // Select your key type. Ed25519 are nice short
	// // 	-1,             // Select key length when possible (i.e. RSA).
	// // )
	// // if err != nil {
	// // 	panic(err)
	// // }

	// id1, _ := peer.IDFromPrivateKey(priv)

	// fmt.Println("Kyber public:", pubTemp.String())
	// pubL, _ := id1.ExtractPublicKey()
	// pubBytes, _ := pubL.Bytes()
	// fmt.Println(hex.EncodeToString(pubBytes))
	// point := publicKeyToEdwards25519KyberPoint(pubBytes)
	// fmt.Println(point.String())

	// privBytes, err := priv.Bytes()
	// if err != nil {
	// 	panic(err)
	// }
	// privStr := hex.EncodeToString(privBytes)

	// keystore := keystoreFile{PrivateKey: privStr, ID: id1.String()}

	// out, err := json.Marshal(keystore)
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Println(string(out))
}
