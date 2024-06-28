//go:build windows
// +build windows

/*
ID: 92984446-aefb-4d5e-ad12-598042ca80ba
NAME: PowerShell Suspicious Script with Clipboard Retrieval Capabilities
CREATED: 2024-06-28
scenario: PowerShell script used to get contents of clipboard
*/
package main

import (
	_ "embed"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"powershell.exe", "-Command", `[Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms"); [System.Windows.Forms.Clipboard]::GetText`},
}

func test() {
	println("[+] Initiating PowerShell script with clipboard retrieval capabilities")

	command := supported[runtime.GOOS]
	_, err := Endpoint.Shell(command)
	if err != nil {
		println("[+] Execution was prevented")
		Endpoint.Stop(100)
		return
	}

	println("[-] Clipboard retrieval script was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}