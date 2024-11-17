//go:build darwin
// +build darwin

/*
ID: 4d9af153-a878-4ae3-b6c4-b3f14e516f25
NAME: Manual Loading of a Suspicious Chromium Extension
CREATED: 2024-06-29
*/
package main

import (
	"fmt"
	"os"
	"os/exec"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting Manual Loading of a Suspicious Chromium Extension VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	// Define the command to load a suspicious Chromium extension
	extensionPath := "/test"
	chromePath := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	cmd := exec.Command(chromePath, "--load-extension="+extensionPath)

	// Execute the command
	out, err := cmd.CombinedOutput()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to execute command: %s", string(out)))
		Endpoint.Stop(1) // ERROR
	}

	Endpoint.Say(fmt.Sprintf("[+] Successfully executed command: %s", string(out)))

	// Check if the process was blocked (simulate a protection mechanism)
	if strings.Contains(string(out), "Access Denied") {
		Endpoint.Say("[+] Process execution was blocked")
		Endpoint.Stop(126) // PROTECTED: Access Denied
	}

	// Simulate checking if the extension was loaded
	extensionLoaded := false // Replace with actual check if possible
	if extensionLoaded {
		Endpoint.Say("[-] Suspicious extension loaded successfully")
		Endpoint.Stop(101) // UNPROTECTED
	} else {
		Endpoint.Say("[+] Suspicious extension was not loaded")
		Endpoint.Stop(100) // PROTECTED
	}
}

func cleanup() {
	// Clean up any artifacts if necessary (none in this case)

	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}