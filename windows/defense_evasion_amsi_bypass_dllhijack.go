//go:build windows
// +build windows

/*
ID: fa488440-04cc-41d7-9279-539387bf2a17
NAME: Suspicious Antimalware Scan Interface DLL
CREATED: 2024-06-25
scenario: creation of AMSI [Anti Malware Scan Interface] DLL in unusual location
bypassing AMSI by loading a rogue AMSI module
*/

package main

import (
	_ "embed"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

//go:embed amsi.dll
var maliciousDLL []byte

func test() {
	filename := "C:\\Temp\\amsi.dll"
	Endpoint.Say("creating rogue AMSI DLL at: " + filename)
	Endpoint.Write(filename, dll)
	if Endpoint.Exists(filename) {
		Endpoint.Say("DLL successfully created")
		Endpoint.Stop(101) // UNPROTECTED
	} else {
		Endpoint.Say("failed to create DLL")
		Endpoint.Stop(100)
	}
}

func main() {
	Endpoint.Start(test)
}