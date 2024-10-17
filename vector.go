package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// enum {...} SignatureScheme
type SignatureScheme uint16

const (
	ECDSA_P256_SHA256 SignatureScheme = 0x0403
	ECDSA_P384_SHA384 SignatureScheme = 0x0503
	ECDSA_P521_SHA512 SignatureScheme = 0x0603
)

var prng = rand.Reader

func main() {
	fmt.Println("Hello")

	emailDERb64 := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmsbPTS/ly/EuvASgpNeFE5ZTV9D4z83jD4T1Wi43aQx30h01Kwxjtk3IfUHR+9wGjCZUsv6pPmym2LHkiq+24w=="

	emailDER, err := base64.StdEncoding.DecodeString(emailDERb64)

	fmt.Println("emailDERb64 ", emailDERb64)
	fmt.Println("emailDER ", emailDER)
	epskid := computeEpskid(emailDER)
	b64 := base64.StdEncoding.EncodeToString(epskid)
	fmt.Println("Base64 of HKDF-Expand (email-epskid) ", b64)

	keyPair, err := newSigningKey(ECDSA_P256_SHA256)
	if err != nil {
		return
	}

	derPublicKey, err := x509.MarshalPKIXPublicKey(keyPair.Public())
	if err != nil {
		panic(err)
	}
	fmt.Println("\nRandom DER ", derPublicKey)

	epskid = computeEpskid(derPublicKey)

	b64 = base64.StdEncoding.EncodeToString(epskid)
	fmt.Println("Base64 of HKDF-Expand (epskid) ", b64)
}

func computeEpskid(der []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(der)
	fmt.Println("Base64 DER of SubjectPublicKeyInfo ", b64)

	extract := HkdfExtract(crypto.SHA256, nil, der)
	b64 = base64.StdEncoding.EncodeToString(extract)
	fmt.Println("Base64 of HKDF-Extract ", b64)

	epskid := HkdfExpand(crypto.SHA256, extract, []byte("tls13-bspsk-identity"), 32)

	return epskid
}

func newSigningKey(sig SignatureScheme) (crypto.Signer, error) {
	switch sig {
	case ECDSA_P256_SHA256:
		return ecdsa.GenerateKey(elliptic.P256(), prng)
	case ECDSA_P384_SHA384:
		return ecdsa.GenerateKey(elliptic.P384(), prng)
	case ECDSA_P521_SHA512:
		return ecdsa.GenerateKey(elliptic.P521(), prng)
	default:
		return nil, fmt.Errorf("tls.newsigningkey: Unsupported signature algorithm [%04x]", sig)
	}
}

func HkdfExtract(hash crypto.Hash, saltIn, input []byte) []byte {
	salt := saltIn

	// if [salt is] not provided, it is set to a string of HashLen zeros
	if salt == nil {
		salt = bytes.Repeat([]byte{0}, hash.Size())
	}

	h := hmac.New(hash.New, salt)
	h.Write(input)
	out := h.Sum(nil)

	fmt.Println("HKDF Extract")
	fmt.Println("Salt ", len(salt), salt)
	fmt.Println("Input ", len(input), input)
	fmt.Println("Output ", len(out), out)

	return out
}

func HkdfExpand(hash crypto.Hash, prk, info []byte, outLen int) []byte {
	out := []byte{}
	T := []byte{}
	i := byte(1)
	for len(out) < outLen {
		block := append(T, info...)
		block = append(block, i)

		h := hmac.New(hash.New, prk)
		h.Write(block)

		T = h.Sum(nil)
		out = append(out, T...)
		i++
	}
	return out[:outLen]
}
