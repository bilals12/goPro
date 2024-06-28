//go:build windows
// +build windows

/*
ID: 7ba58110-ae13-439b-8192-357b0fcfa9d7
NAME: Suspicious LSASS Access via MalSecLogon
CREATED: 2024-06-28
scenario: suspicious access to the Local Security Authority Subsystem Service (LSASS) handle from a call trace pointing to seclogon.dll with a suspicious access rights value. 
Uses cmd.exe to simulate suspicious access to LSASS via seclogon.dll with specific access rights (0x14c0)
*/
package main

import (
	_ "embed"
	"runtime"
	"os/exec"
	"syscall"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"cmd.exe", "/C", "echo Test for LSASS access via MalSecLogon"},
}

func test() {
	println("[+] Initiating suspicious LSASS access via MalSecLogon")

	command := supported[runtime.GOOS]
	cmd := exec.Command(command[0], command[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}

	// Simulate the suspicious access to LSASS
	cmd.SysProcAttr.Token = syscall.Token(0x14c0)
	err := cmd.Run()
	if err != nil {
		println("[+] Execution was prevented")
		Endpoint.Stop(100)
		return
	}

	println("[-] Suspicious LSASS access was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}
