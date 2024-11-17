//go:build windows
// +build windows

/*
ID: 24082642-49a7-4072-952b-10c244b24f8e
NAME: Potential Self Deletion of a Running Executable
CREATED: 2024-07-01
scenario: execution of file followed by rename of its primary file stream
attempt to delete currently running PE file on disk
bypassing file lock restriction
delete files left behind by actions of their intrusion
*/
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting Potential Self Deletion of a Running Executable VST")
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

	// Simulate execution of a file followed by the rename of its primary file stream
	executablePath := "C:\\Users\\Public\\self_delete_test.exe"
	renamedPath := "C:\\Users\\Public\\self_delete_test.exe:delete"
	executeCommand(fmt.Sprintf("powershell.exe -Command New-Item -Path %s -ItemType File", executablePath))

	// Run the executable
	executeCommand(fmt.Sprintf("start %s", executablePath))

	// Rename the primary file stream
	executeCommand(fmt.Sprintf("powershell.exe -Command Rename-Item -Path %s -NewName %s", executablePath, renamedPath))

	// Check the rename action
	if _, err := os.Stat(renamedPath); os.IsNotExist(err) {
		Endpoint.Say("[-] Renamed file does not exist")
		Endpoint.Stop(101) // UNPROTECTED
	}

	Endpoint.Stop(100) // PROTECTED
}

func cleanup() {
	// Remove the created files
	os.Remove("C:\\Users\\Public\\self_delete_test.exe")
	os.Remove("C:\\Users\\Public\\self_delete_test.exe:delete")

	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}
