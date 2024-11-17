//go:build windows
// +build windows

/*
ID: b8a0a3aa-0345-4035-b41d-f758a6c59a78
NAME: Command Shell Activity Started via RunDLL32
CREATED: 2024-07-01
scenario: command shell activity started via RunDLL32
used by attackers to host malicious code
*/
package main

import (
	"fmt"
	"os/exec"
	"strings"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting Command Shell Activity Started via RunDLL32 VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	executeCommand := func(command string) {
		if !Endpoint.IsAvailable("cmd.exe") {
			Endpoint.Say("[+] Command execution is not available")
			Endpoint.Stop(126) // PROTECTED: Access Denied
		}

		out, err := exec.Command("cmd.exe", "/C", command).CombinedOutput()
		if err != nil {
			Endpoint.Say(fmt.Sprintf("[-] Failed to execute command: %s", string(out)))
			Endpoint.Stop(1) // ERROR
		}

		Endpoint.Say(fmt.Sprintf("[+] Successfully executed command: %s", command))

		if strings.Contains(string(out), "Access Denied") {
			Endpoint.Say("[+] Process execution was blocked")
			Endpoint.Stop(126) // PROTECTED: Access Denied
		}
	}

	// Simulate rundll32.exe launching a command shell (cmd.exe) with a malicious command
	rundll32Path := "C:\\Windows\\System32\\rundll32.exe"
	cmdPath := "C:\\Windows\\System32\\cmd.exe"
	rundll32Cmd := fmt.Sprintf("%s %s", rundll32Path, cmdPath)
	executeCommand(rundll32Cmd)

	// Simulate rundll32.exe launching PowerShell with a malicious command
	powershellPath := "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
	rundll32PowershellCmd := fmt.Sprintf("%s %s", rundll32Path, powershellPath)
	executeCommand(rundll32PowershellCmd)

	Endpoint.Stop(100) // PROTECTED
}

func cleanup() {
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}
