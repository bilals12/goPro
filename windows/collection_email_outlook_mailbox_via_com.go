//go:build windows
// +build windows

/*
ID: 1dee0500-4aeb-44ca-b24b-4a285d7b6ba1
NAME: Suspicious Inter-Process Communication via Outlook
CREATED: 2024-06-28
Scenario: unusual process attempts to communicate with Outlook via COM [Component Object Model].
adversaries may use it to access user email for collecting sensitive information or sending emails on behalf of user.
*/
package main

import (
	_ "embed"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"powershell.exe", "-Command", `New-Object -ComObject Outlook.Application`},
}

func test() {
	println("[+] Initiating suspicious COM interaction with Outlook via PowerShell")

	command := supported[runtime.GOOS]
	_, err := Endpoint.Shell(command)
	if err != nil {
		println("[+] Execution was prevented")
		Endpoint.Stop(100)
		return
	}

	println("[-] COM interaction was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}