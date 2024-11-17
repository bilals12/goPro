//go:build windows
// +build windows

/*
ID: unique-id-iatcamo
NAME: IAT Camouflage Detection
CREATED: 2024-07-02
*/
package main

import (
	"fmt"
	"os/exec"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting IAT Camouflage Detection VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	// Simulate IAT Camouflage
	command := "rundll32.exe shell32.dll,Control_RunDLL"

	out, err := exec.Command("cmd.exe", "/C", command).CombinedOutput()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to execute IAT camouflage: %s", string(out)))
		Endpoint.Stop(1) // ERROR
	}

	Endpoint.Say("[+] Successfully executed IAT camouflage")
	Endpoint.Stop(101) // UNPROTECTED: Malicious behavior not blocked
}

func cleanup() {
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}
