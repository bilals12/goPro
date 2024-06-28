//go:build darwin
// +build darwin

/*
ID: 41b638a1-8ab6-4f8e-86d9-466317ef2db5
NAME: Potential Hidden Local User Account Creation
CREATED: 2024-06-28
scenario: attempt made to create local user account on macOS that's hidden from logon window
Hidden User Account Command: Uses the dscl command to create a hidden local user account on macOS. The IsHidden attribute is set to 1 to hide the account from the logon window.
*/
package main

import (
	_ "embed"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"darwin": {"dscl", ".", "-create", "/Users/hiddenuser", "UserShell", "/bin/bash", "IsHidden", "1"}
}

func test() {
	println("[+] Creating a hidden local user account on macOS")

	command := supported[runtime.GOOS]
	_, err := Endpoint.Shell(command)
	if err != nil {
		println("[+] Execution was prevented")
		Endpoint.Stop(100)
		return
	}

	println("[-] Hidden user account creation was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}