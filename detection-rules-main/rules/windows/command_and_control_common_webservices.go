//go:build windows
// +build windows

/*
ID: 66883649-f908-4a5b-a1e0-54090a1d3a32
NAME: Connection to Commonly Abused Web Services
CREATED: 2024-06-28
*/

package main

import (
	_ "embed"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[strings][]string{
	"windows": {
		"cmd.exe", "/C", "powershell -Command \"Invoke-WebRequest -Uri 'https://pastebin.com' -OutFile 'C:\\Windows\\Temp\\output.html'\"",
	},
}

func test() {
	println("[+] Initiating web request to commonly abused web service")

	command := supported[runtime.GOOS]
	_, err := Endpoint.Shell(command)
	if err != nil {
		println("[+] Execution was prevented")
		Endpoint.Stop(100)
		return
	}

	println("[-] Web request was not blocked")
	Endpoint.Stop(101)
}