//go:build windows
// +build windows

/*
ID: c7894234-7814-44c2-92a9-f7d851ea246a
NAME: Unusual Network Connection via DllHost
CREATED: 2024-06-28
scenario: dllhost.exe not usually used for network comms
*/

package main

import (
	_ "embed"
	"runtime"
	"os/exec"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"dllhost.exe"},
}

func test(){
	// check for `dllhost.exe`
	if !Endpoint.Exists("C:\\Windows\\System32\\dllhost.exe") {
		Endpoint.Say("dllhost.exe not found")
		Endpoint.Stop(104) // NOT RELEVANT
		return
	}

	// attempt to make outbound connection
	Endpoint.Say("[+] attempting to make outbound connection via dllhost.exe")
	command := supported[runtime.GOOS]
	args := []string{"-c", "dllhost.exe", "https://google.com"}

	_, err := Endpoint.Shell(args)
	if err != nil {
		Endpoint.Say("[+] network connection blocked")
		Endpoint.Stop(106) // PROTECTED: Network Connection Blocked
		return
	}

	Endpoint.Say("[-] Network connection was not blocked")
	Endpoint.Stop(101) // UNPROTECTED: Network connection was successful
}

func main() {
	Endpoint.Start(test)
}