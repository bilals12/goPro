//go:build windows
// +build windows

/*
ID: unique-id-hasher
NAME: CRC32 Hashing Detection
CREATED: 2024-07-02
*/
package main

import (
	"fmt"
	"os/exec"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting CRC32 Hashing Detection VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	// Simulate hashing a string using CRC32
	inputString := "example_string"
	command := fmt.Sprintf("CRC32B %s", inputString)

	out, err := exec.Command("cmd.exe", "/C", command).CombinedOutput()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to compute CRC32 hash: %s", string(out)))
		Endpoint.Stop(1) // ERROR
	}

	Endpoint.Say("[+] Successfully computed CRC32 hash")
	Endpoint.Stop(101) // UNPROTECTED: Malicious behavior not blocked
}

func cleanup() {
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}
