//go:build windows
// +build windows

/*
ID: ace0bb76-290f-4f5f-a21f-c3b13ee415a9
NAME: Potential Masquerading as Windows Error Manager
CREATED: 2024-06-29
scenario: suspicious instances of WerFault.exe/Wermgr.exe with a suspicious parent call stack
evading detection of suspicious child process behaviour
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
	Endpoint.Say("[+] Starting Potential Masquerading as Windows Error Manager VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	commands := []string{
		"WerFault.exe",
		"wermgr.exe",
		"WerFaultSecure.exe"
	}

	for _, command := range commands {
		if !Endpoint.IsAvailable("cmd.exe") {
			Endpoint.Say("command execution not available")
			Endpoint.Stop(126) // PROTECTED
		}

		out, err := execCommand("cmd.exe", "/C", command).CombinedOutput()
		if err != nil {
			Endpoint.Say(fmt.Sprintf("failed to execute: %s", string(out)))
			Endpoint.Stop(1) // ERROR
		}
		Endpoint.Say(fmt.Sprintf("successfully executed command: %s", string(out)))

		if strings.Contains(string(out), "Access Denied"){
			Endpoint.Say("process execution blocked")
			Endpoint.Stop(126) // PROTECTED
		}
	}
	Endpoint.Say("successfully executed all commands")
	Endpoint.Stop(101) // UNPROTECTED
}

func cleanup() {
	commands := []string {
		"taskkill /F /IM WerFault.exe",
		"taskkill /F /IM wermgr.exe",
		"taskkill /F /IM WerFaultSecure.exe",
	}

	for _, command := range commands {
		err := exec.Command("cmd.exe", "/C", command).Run()
		if err != nil {
			Endpoint.Say(fmt.Sprintf("failed to kill process %s: %s", command, err))
		} else {
			Endpoint.Say(fmt.Sprintf("killed process %s", command))
		}
	}
	Endpoint.Say("cleanup completed!")
	Endpoint.Stop(100) // PROTECTED
}