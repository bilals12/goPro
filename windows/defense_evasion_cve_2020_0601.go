//go:build windows
// +build windows

/*
ID: 56557cde-d923-4b88-adee-c61b3f3b5dc3
NAME: Windows CryptoAPI Spoofing Vulnerability (CVE-2020-0601 - CurveBall)
CREATED: 2024-06-30
scenario: spoofing of ECC certs
*/

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

// create spoof ECDSA cert
func GenerateSpoofedCert() ([]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365*24*time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		SubjectL pkix.Name{
			Organization: []string{"Trusted Organization"},
		},
		NotBefore: notBefore,
		NotAfter: notAfter,
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsageL []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEM, nil
}

func test() {
	println("[+] Generating spoofed certificate to simulate CVE-2020-0601")
	cert, err := GenerateSpoofedCert()
	if err != nil {
		fmt.Printf("[-] error generating cert: %v\n", err)
		Endpoint.Stop(256) // unexpected error code
	}
	println("[+] Writing spoofed certificate to file for detection")
	err = os.WriteFile("spoofed_cert.pem", cert, 0644)
	if err != nil {
		fmt.Printf("[-] error writing cert to file: %v\n", err)
		Endpoint.Stop(256) // unexpected error
	}

	println("[+] pausing to gauge defense")
	Endpoint.Wait(3)

	if Endpoint.Exists("spoofed_cert.pem") {
		println("[-] spoofed cert not detected or removed")
		Endpoint.Stop(101) // unprotected
	} else {
		println("[+] spoofed cert detected + removed")
		Endpoint.Stop(105) // Protected: file quarantined
	}
}

func main() {
	Endpoint.Start(test)
}