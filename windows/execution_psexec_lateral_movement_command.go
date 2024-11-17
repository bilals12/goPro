//go:build windows
// +build windows

/*
ID: 55d551c6-333b-4665-ab7e-5d14a59715ce
NAME: PsExec Network Connection
CREATED: 2024-06-29
Description: This test simulates the execution of PsExec.exe with the -accepteula flag and makes a network connection to identify potential lateral movement.
*/
package main

import (
	_ "embed"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"PsExec.exe", "-accepteula", "\\\\localhost", "ipconfig"},
}

func test() {
	println("[+] Initiating PsExec execution with network connection")

	command := supported[runtime.GOOS]
	_, err := Endpoint.Shell(command)
	if err != nil {
		println("[+] Execution was prevented")
		Endpoint.Stop(100)
		return
	}

	println("[-] PsExec execution with network connection was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}