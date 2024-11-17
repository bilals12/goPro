//go:build windows
// +build windows

/*
ID: 93c1ce76-494c-4f01-8167-35edfb52f7b1
NAME: Encoded Executable Stored in the Registry
CREATED: 2020-11-25
scenario: storing malicious executable content in registry to evade detection
*/

package main

import (
	Endpoint "github.com/preludeorg/test/endpoint"
	"encoding/base64"
	"golang.org/x/sys/windows/registry"
	"runtime"
)

var encodedPE = "TVqQAAMAAAAEAAAA*"

func test() {
	// decode b64 executable
	decodedPE, err := base64.StdEncoding.DecodedString(encodedPE)
	if err != nil {
		Endpoint.Say("failed to decode encoded PE")
		Endpoint.Stop(1) // error
		return
	}

	// write decoded PE to reg
	Endpoint.Say("[+] writing decoded PE to registry")

	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Malicious`, registry.SET_VALUE)
	if err != nil {
		Endpoint.Say("failed to create registry key")
		Endpoint.Stop(1) // error
		return
	}
	defer key.Close()

	err = key.SetBinaryValue("MaliciousExecutable", decodedPE)
	if err != nil {
		Endpoint.Say("failed to set registry value")
		Endpoint.Stop(1) // error
		return
	}

	// check if registry modification was detected + blocked
	if Endpoint.Exists(`HKEY_CURRENT_USER\Software\Malicious`) {
		Endpoint.Say("[-] registry modification not blocked")
		Endpoint.Stop(101) // UNPROTECTED
	} else {
		Endpoint.Say("[+] registry modification blocked")
		Endpoint.Stop(100) // PROTECTED
	}
}
func main() {
	Endpoint.Start(test)
}