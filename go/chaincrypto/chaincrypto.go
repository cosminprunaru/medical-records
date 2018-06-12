package chaincrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
)

/*
GenerateKeysAndSave -> create a set of public/private RSA keys
and save them
@bitSize - length of the key
@filename - where the keys will be saved
*/
func GenerateKeysAndSave(bitSize int, filename string) {
	reader := rand.Reader

	key, err := rsa.GenerateKey(reader, bitSize)
	checkError(err)

	publicKey := key.PublicKey

	saveGobKey(filename+"private.key", key)
	savePEMKey(filename+"private.pem", key)

	saveGobKey(filename+"public.key", publicKey)
	savePublicPEMKey(filename+"public.pem", publicKey)
}

func saveGobKey(fileName string, key interface{}) {
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	encoder := gob.NewEncoder(outFile)
	err = encoder.Encode(key)
	checkError(err)
}

func savePEMKey(fileName string, key *rsa.PrivateKey) {
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	checkError(err)
}

func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	checkError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error: ", err.Error())
	}
}

/*******************************************************
					ECDSA keys
*******************************************************/

/*
ECDSASignature -> struct for signing blocks
*/
type ECDSASignature struct {
	R, S *big.Int
}

/*
GenerateECDSAKeys -> function that generates ECDSA keys and saves them to a file
*/
func GenerateECDSAKeys(filename string) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	outFile, err := os.Create(filename + "ecdsa-private.key")
	checkError(err)
	defer outFile.Close()

	b, _ := x509.MarshalECPrivateKey(priv)

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}

	err = pem.Encode(outFile, privateKey)
	checkError(err)
}

func savePublicECDSAKey(fileName string, pubkey ecdsa.PublicKey) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	checkError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	checkError(err)
}

/*
ReadECDSAfromFile -> read private key form file,
which also contains the public key
*/
func ReadECDSAfromFile(keyPath string) *ecdsa.PrivateKey {
	raw, err := ioutil.ReadFile(keyPath)

	if err != nil {
		log.Println(err)
		return nil
	}

	private, err := parseECPrivateKeyFromPEM(raw)

	if err != nil {
		log.Println(err)
		return nil
	}

	return private
}

func parseECPrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, nil
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
		return nil, err
	}

	var pkey *ecdsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
		return nil, nil
	}

	return pkey, nil
}

/*
SignMessage -> fucntion that will sign a bytes array with a private ECDSA
key which can be later be verified
*/
func SignMessage(priv *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	hashed := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hashed[:])
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(ECDSASignature{r, s})
}

/*
VerifyMessage -> function that verifies the intergity of a message based
on its signature
*/
func VerifyMessage(pub *ecdsa.PublicKey, message []byte, signature []byte) bool {
	var rs ECDSASignature

	if _, err := asn1.Unmarshal(signature, &rs); err != nil {
		return false
	}

	hashed := sha256.Sum256(message)
	return ecdsa.Verify(pub, hashed[:], rs.R, rs.S)
}
