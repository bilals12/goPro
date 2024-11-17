//go:build linux
// +build linux

/*
ID: e7075e8d-a966-458e-a183-85cd331af255
NAME: Default Cobalt Strike Team Server Certificate
CREATED: 2023-12-18
scenario: compare cert hashes to known CS cert hashes
*/

package main

import (
    "crypto/tls"
    "crypto/x509"
    "encoding/hex"
    Endpoint "github.com/preludeorg/test/endpoint"
    Network "github.com/preludeorg/test/network"
)

func test() {
    targetURL := "https://example.com"
    expectedMD5Hash := "950098276A495286EB2A2556FBAB6D83"
    expectedSHA1Hash := "6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C"
    expectedSHA256Hash := "87F2085C32B6A2CC709B365F55873E207A9CAA10BFFECF2FD16D3CF9D94D390C"

    httpClient := Network.NewHTTPRequest(targetURL, nil)
    tlsConfig := &tls.Config{
        InsecureSkipVerify: true,
    }

    conn, err := tls.Dial("tcp", "example.com:443", tlsConfig)
    if err != nil {
        Endpoint.Say("TLS connection failed")
        Endpoint.Stop(126)
    }
    defer conn.Close()

    cert := conn.ConnectionState().PeerCertificates[0]
    md5Hash := hex.EncodeToString(cert.Signature[:16])
    sha1Hash := hex.EncodeToString(cert.Signature[:20])
    sha256Hash := hex.EncodeToString(cert.Signature[:32])

    if md5Hash == expectedMD5Hash || sha1Hash == expectedSHA1Hash || sha256Hash == expectedSHA256Hash {
        Endpoint.Say("default CS TeamServer cert detected")
        Endpoint.Stop(101) // unprotected
    } else {
        Endpoint.Say("no matching certs detected")
        Endpoint.Stop(100) // protected
    }

}

func main() {
    Endpoint.Start(test)
}