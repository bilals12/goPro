//go:build windows
// +build windows

/*
ID: 290aca65-e94d-403b-ba0f-62f320e63f51
NAME: UAC Bypass Attempt via Windows Directory Masquerading
CREATED: 2024-06-29
*/

package main

import (
	"os/exec"
	"runtime"
	"strings"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"cmd.exe", "/C", "echo Bypassing UAC > C:\\Windows \\system32\\UACBypassTest.txt"},
}

func test() {
	command := supported[runtime.GOOS]
	exe := strings.Join(command, " ")
	cmd := exec.Command("cmd.exe", "/C", exe)

	Endpoint.Say("[+] Attempting UAC Bypass by masquerading as a trusted Windows directory")
	err := cmd.Run()
	if err != nil {
		Endpoint.Say("[-] UAC Bypass attempt failed: " + err.Error())
		Endpoint.Stop(101)
		return
	}

	Endpoint.Say("[+] UAC Bypass attempt completed")
	Endpoint.Stop(100)
}

func main() {
	Endpoint.Start(test)
}