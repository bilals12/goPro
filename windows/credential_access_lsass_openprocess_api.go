//go:build windows
// +build windows

/*
ID: ff4599cb-409f-4910-a239-52e4e6f532ff
NAME: LSASS Process Access via Windows API
CREATED: 2024-06-29
scenario: accessing LSASS via WinAPI calls [OpenProcess, OpenThread]
*/

package main

import (
	"os/exec"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"cmd.exe", "/C", "powershell.exe", "-Command", `"[DllImport(\"kernel32.dll\", SetLastError = true, CharSet = CharSet.Auto)] public static extern IntPtr OpenProcess(int processAccess, bool bInheritHandle, int processId);"`},
}

func test() {
	Endpoint.Say("[+] simulating LSASS process access via WinAPI")

	cmd := exec.Command("powershell.exe", "-Command", `"[DllImport(\"kernel32.dll\", SetLastError = true, CharSet = CharSet.Auto)] public static extern IntPtr OpenProcess(int processAccess, bool bInheritHandle, int processId);"`)
	err := cmd.Run()
	if err != nil {
		Endpoint.Say("[-] Failed to simulate LSASS process access: " + err.Error())
		Endpoint.Stop(101)
		return
	}

	Endpoint.Say("[+] LSASS process access simulation complete")
	Endpoint.Stop(100)
}

func main() {
	Endpoint.Start(test)
}