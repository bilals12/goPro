//go:build windows
// +build windows

/*
ID: 667a1895-5920-4fb2-820f-16c356f79341
NAME: Suspicious Process with a Spoofed Parent
CREATED: 2024-06-29
scenario: attempts to start process with fake parent process identity to blend in with normal child process

*/
package main

import (
	"fmt"
	"os/exec"
	"strings"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting Suspicious Process with a Spoofed Parent VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	// suspicious process with spoofed parent
	commands := []string {
		"powershell.exe Invoke-InProcessStup -execWrapper \"ANSIBLE_BOOTSTRAP_ERROR:\"",
		"WerFault.exe",
	}

	for _, command := range commands {
		if !Endpoint.IsAvailable("cmd.exe") {
			Endpoint.Say("command execution not available")
			Endpoint.Stop(126) // PROTECTED
		}

		out, err := exec.Command("cmd.exe", "/C", command).CombinedOutput()
		if err != nil {
			Endpoint.Say(fmt.Sprintf("failed to execute command: %s", string(out)))
			Endpoint.Stop(1) // ERROR
		}

		Endpoint.Say(fmt.Sprintf("successfully executed command: %s", command))

		if strings.Contains(string(out), "Access Denied") {
			Endpoint.Say("process execution blocked")
			Endpoint.Stop(126) // PROTECTED
		}
	}

	// API call with WriteProcessMemory
	apiCommand := "powershell.exe -Command \"[DllImport('kernel32.dll')] public static extern IntPtr WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);\""
	out, err := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", apiCommand).CombinedOutput()
	if err! = nil {
		Endpoint.Say(fmt.Sprintf("failed to execute API command: %s", string(out)))
		Endpoint.Stop(1) // ERROR
	}

	Endpoint.Say("successfully executed API command")
	Endpoint.Stop(101) // UNPROTECTED
}

func cleanup() {
	commands := []string{
		"taskkill /F /IM powershell.exe",
		"taskkill /F /IM WerFault.exe",
	}

	for _, command := range commands {
		err := exec.Command("cmd.exe", "/C", command).Run()
		if err != nil {
			Endpoint.Say(fmt.Sprintf("failed to kill process %s: %s", command, err))
		} else {
			Endpoint.Say(fmt.Sprintf("killed process %s", command))
		}
	}
	Endpoint.Say("cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTEd
}