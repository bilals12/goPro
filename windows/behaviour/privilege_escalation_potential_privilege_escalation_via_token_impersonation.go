//go:build windows
// +build windows

/*
ID: 46de65b8-b873-4ae7-988d-12dcdc6fa605
NAME: Potential Privilege Escalation via Token Impersonation
CREATED: 2024-06-29
scenario: new proc created with token impersonating windows binary
*/

package main

import (
	_ "embed"
	"os/exec"
	"runtime"
	"syscall"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"cmd.exe", "/C", "echo Potential privilege escalation via token impersonation"},
}

func test() {
	command := supported[runtime.GOOS]
	Endpoint.Say("[+] simulating proc creation via token impersonation")

	cmd := exec.Command(command[0], command[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
		Token: syscall.Token(0x1234678),
		NoInheritHandles: true,
	}
	err := cmd.Run()
	if err != nil {
		Endpoint.Say("[-] Process creation failed: " + err.Error())
		Endpoint.Stop(101)
		return
	}

	Endpoint.Say("[+] Process created successfully with impersonated token")
	Endpoint.Stop(100)
}

func main() {
	Endpoint.Start(test)
}