//go:build windows
// +build windows

/*
ID: unique-id-unhook
NAME: DLL Unhooking Detection
CREATED: 2024-07-02
*/
package main

import (
	"os/exec"
	"syscall"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting DLL Unhooking Detection VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	// simulate DLL unhooking
	commands := [][]string {
		{"cmd.exe", "/C", "rundll32.exe unhook.dll,UnhookAllLoadedDlls"},
	}

	for _, command := range commands {
		_, err := exec.Command(command[0], command[1:]...).CombinedOutput()
		if err != nil {
			Endpoint.Say("failed to execute command")
			Endpoint.Stop(1) // ERROR
		}
	}
	Endpoint.Say("successfully executed unhook command")
	Endpoint.Stop(101) // UNPROTECTED
}

func cleanup