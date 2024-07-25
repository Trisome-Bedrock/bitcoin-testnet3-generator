package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

func generateKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func privateKeyToWIF(privateKey *ecdsa.PrivateKey) string {
	privKeyBytes := privateKey.D.Bytes()
	privKeyBytes = append([]byte{0xEF}, privKeyBytes...) // 0xEF is the version byte for Testnet3 WIF
	checksum := doubleSHA256(privKeyBytes)[:4]
	fullKey := append(privKeyBytes, checksum...)
	return base58.Encode(fullKey)
}

func publicKeyToAddress(publicKey []byte) string {
	sha256Hash := sha256.Sum256(publicKey)
	ripemd160Hasher := ripemd160.New()
	_, err := ripemd160Hasher.Write(sha256Hash[:])
	if err != nil {
		log.Fatal(err)
	}
	pubKeyHash := ripemd160Hasher.Sum(nil)
	versionedPayload := append([]byte{0x6F}, pubKeyHash...) // 0x6F is the version byte for Testnet3
	checksum := doubleSHA256(versionedPayload)[:4]
	fullPayload := append(versionedPayload, checksum...)
	return base58.Encode(fullPayload)
}

func doubleSHA256(data []byte) []byte {
	hash1 := sha256.Sum256(data)
	hash2 := sha256.Sum256(hash1[:])
	return hash2[:]
}

func main() {
	privateKey, err := generateKeyPair()
	if err != nil {
		log.Fatal("Error generating key pair:", err)
	}

	publicKey := elliptic.Marshal(elliptic.P256(), privateKey.X, privateKey.Y)

	wif := privateKeyToWIF(privateKey)
	address := publicKeyToAddress(publicKey)

	fmt.Println("Bitcoin Testnet3 Private Key (WIF):", wif)
	fmt.Println("Bitcoin Testnet3 Address:", address)
	fmt.Println("Public Key (hex):", hex.EncodeToString(publicKey))
}
