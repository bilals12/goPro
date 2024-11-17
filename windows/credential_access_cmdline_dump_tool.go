//go:build windows
// +build windows

/*
ID: 00140285-b827-4aee-aa09-8113f58a08f3
NAME: Potential Credential Access via Windows Utilities
CREATED: 2024-07-
scenario: known windows utils used to dump LSASS or AD database [NTDS.dit]
*/
package main

import (
	"fmt"
	"os/exec"
	"strings"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting Potential Credential Access via Windows Utilities VST")
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

	// execution of utils
	utilities := []struct {
		Name string
		Command string
	}{
		{"procdump.exe", "procdump.exe -ma"},
		{"ProcessDump.exe", "ProcessDump.exe"},
		{"WriteMiniDump.exe", "WriteMiniDump.exe"},
		{"RUNDLL32.exe", "rundll32.exe comsvcs.dll,#24"},
		{"RdrLeakDiag.exe", "RdrLeakDiag.exe /fullmemdmp"},
		{"SqlDumper.exe", "SqlDumper.exe 0x01100"},
		{"TTTrace.exe", "TTTracer.exe -dumpFull -attach"},
		{"ntdsutil.exe", "ntdsutil.exe create full"},
		{"diskshadow.exe", "diskshadow.exe /s"},
	}
	for _, utility := range utilities {
		Endpoint.Say(fmt.Sprintf("simulating %s", utility.Name))
		executeCommand(utility.Command)
	}
	Endpoint.Say("simulation completed successfully")
	Endpoint.Stop(100) // PROTECTED
}

func cleanup() {
	Endpoint.Say("cleanup completed!")
	Endpoint.Stop(100) // PROTECTED
}