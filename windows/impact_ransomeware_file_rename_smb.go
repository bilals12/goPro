//go:build windows
// +build windows

/*
ID: 78e9b5d5-7c07-40a7-a591-3dbbf464c386
NAME: Suspicious File Renamed via SMB
CREATED: 2024-05-21
*/

package main

import (
	"runtime"
	"os/exec"
	"strings"
	"time"
	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"cmd.exe", "/C", "rename", "C:\\Users\\Public\\Documents\\testfile.txt", "C:\\Users\\Public\\Documents\\testfile.enc"},
}

func simulateSMBConnection() {
	println("[+] Simulating incoming SMB connection")
	// Add more complex logic if needed to simulate actual SMB connection attempts
	time.Sleep(3 * time.Second)
}

func test() {
	// Step 1: Simulate incoming SMB connection
	simulateSMBConnection()

	// Step 2: Simulate file rename operation
	println("[+] Simulating file rename operation via SMB")

	command := supported[runtime.GOOS]
	cmd := exec.Command(command[0], command[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "Access is denied") {
			println("[+] File rename operation was blocked")
			Endpoint.Stop(126)
		} else {
			println("[+] Execution error: ", err)
			Endpoint.Stop(256)
		}
		return
	}

	println("[-] File rename operation was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}
