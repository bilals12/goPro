//go:build windows
// +build windows

/*
ID: db7dbad5-08d2-4d25-b9b1-d3a1e4a15efd
NAME: Execution via Windows Subsystem for Linux
CREATED: 2023-01-12
*/

package main

import (
	_ "embed"
	"runtime"
	"os/exec"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"wsl.exe", "-e", "cmd.exe", "/C", "echo WSL test"},
}

func test() {
	println("[+] Initiating execution via Windows Subsystem for Linux")

	command := supported[runtime.GOOS]
	cmd := exec.Command(command[0], command[1:]...)

	err := cmd.Run()
	if err != nil {
		println("[+] Execution was prevented")
		Endpoint.Stop(100)
		return
	}

	println("[-] Execution via WSL was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}