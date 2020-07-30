package main

import (
	"encoding/hex"
	"fmt"

	"github.com/libp2p/go-libp2p-core/crypto"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

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
	// suite := edwards25519.NewBlakeSHA256Ed25519()
	// rand := suite.RandomStream()
	// privTemp := suite.Scalar().Pick(rand) // create a private key x
	// pubTemp := suite.Point().Mul(privTemp, nil)
	priv, _, err := crypto.GenerateKeyPair(
		crypto.Ed25519, // Select your key type. Ed25519 are nice short
		-1,             // Select key length when possible (i.e. RSA).
	)
	if err != nil {
		panic(err)
	}

	// b, _ := privTemp.MarshalBinary()
	// fmt.Println(b[:32])
	// buf1 := bytes.NewBuffer(b)
	// priv, _, err := crypto.GenerateEd25519Key(rand)
	// if err != nil {
	// 	panic(err)
	// }

	// pub := priv.GetPublic()
	// pubBytes1, _ := pub.Raw()
	// pubStr1 := hex.EncodeToString(pubBytes1)
	// pubBytes2, _ := pub.Bytes()
	// pubStr2 := hex.EncodeToString(pubBytes2)
	// fmt.Println(pubStr1)
	// fmt.Println(pubStr2)

	// point := publicKeyToEdwards25519KyberPoint(pubBytes1)
	// pubBytes3, _ := point.MarshalBinary()
	// pubStr3 := hex.EncodeToString(pubBytes3)
	// fmt.Println(pubStr3)

	buf, _ := priv.Raw()
	// fmt.Println(buf[:32])
	privBuf := make([]byte, 32)
	copy(privBuf, buf[:32])
	scalar := privateKeyToEdwards25519KyberPoint(privBuf)
	privBytes, err := scalar.MarshalBinary()
	if err != nil {
		panic(err)
	}
	bufStr := hex.EncodeToString(buf)
	privStr := hex.EncodeToString(privBytes)
	fmt.Println("--")
	fmt.Println(bufStr)
	fmt.Println(privStr)

	// pub1 := priv.GetPublic()
	// pub2 := suite.Point().Mul(scalar, nil)

	// pubBytes1, _ := pub1.Raw()
	// pubStr1 := hex.EncodeToString(pubBytes1)
	// pubBytes2, _ := pub2.MarshalBinary()
	// pubStr2 := hex.EncodeToString(pubBytes2)
	// fmt.Println("--")
	// fmt.Println(pubStr1)
	// fmt.Println(pubStr2)

	// rand := suite.RandomStream()
	// priv2 := suite.Scalar().Pick(rand) // create a private key x
	// privBytes2, err := priv2.MarshalBinary()
	// if err != nil {
	// 	panic(err)
	// }
	// privStr2 := hex.EncodeToString(privBytes2)
	// fmt.Println("--")
	// fmt.Println(privStr2)
}
