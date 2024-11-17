//go:build windows
// +build windows

/*
ID: ae4b2807-3a16-485e-bb69-5d36bbe9b7d1
NAME: Library Loaded via a CallBack Function
CREATED: 2024-06-29
scenario: testing PE that will load ws2_32 and dnsapi.dll via a Callback function using RtlQueueWorkItem and RtlRegisterWait
https://gist.github.com/joe-desimone/0b2bb00eca4c522ba0bd5541a6f3528b
*/
package main

import (
	"fmt"
	"os"
	"os/exec"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting Library Loaded via a CallBack Function VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	bin := "loadlib-callback64.exe"
	if !Endpoint.Exists(bin) {
		Endpoint.Say(fmt.Sprintf("file %s does not exist", bin))
		Endpoint.Stop(104) // not relevant
	}

	Endpoint.Say(fmt.Sprintf("file %s to be executed", bin))

	// execute binary
	out, err := exec.Command(bin).CombinedOutput()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("failed to execute binary: %s", string(out)))
		Endpoint.Stop(1) // ERROR
	}

	Endpoint.Say(fmt.Sprintf("successfully executed binary: %s", string(out)))

	// check if process was blocked
	if strings.Contains(string(out), "Access Denied") {
		Endpoint.Say("process execution blocked")
		Endpoint.Stop(126) // PROTECTED
	}

	// kill process if running
	out, err = exec.Command("taskkill", "/f", "/im", "loadlib-callback64.exe").CombinedOutput()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("failed to kill process: %s", string(out)))
		Endpoint.Stop(1)
	}

	Endpoint.Say("successfully killed process")
	Endpoint.Stop(101) // UNPROTECTED
}

func cleanup() {
	err := exec.Command("taskkill", "/f", "/im", "LoadLib-Callback64.exe").Run()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to cleanup: %s", err))
	} else {
		Endpoint.Say("[+] Cleanup completed successfully")
	}

	Endpoint.Stop(100) // PROTECTED
}