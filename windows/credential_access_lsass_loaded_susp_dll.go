//go:build windows
// +build windows

/*
ID: 3a6001a0-0939-4bbe-86f4-47d8faeb7b97
NAME: Suspicious Module Loaded by LSASS
CREATED: 2024-06-29
scenario: SSP DLLs are loaded into LSASS proc at system start
these DLLs have access to encrypted/plaintext passwords [logged-on user domain passwords, PINs]
*/

package main

import (
	_ "embed"
	"os/exec"
	"runtime"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"cmd.exe", "/C", "echo Simulating LSASS loading an unsigned DLL"},
}

func test() {
	Endpoint.Say("[+] simulating LSASS loading unsigned DLL")

	cmd := exec.Command("cmd.exe", "/C", "rundll32.exe unsigned.dll,EntryPoint")
	err := cmd.Run()
	if err != nil {
		Endpoint.Say("[-] Failed to simulate DLL loading: " + err.Error())
		Endpoint.Stop(101)
		return
	}

	Endpoint.Say("[+] LSASS successfully simulated loading an unsigned DLL")
	Endpoint.Stop(100)
}

func main() {
	Endpoint.Start(test)
}