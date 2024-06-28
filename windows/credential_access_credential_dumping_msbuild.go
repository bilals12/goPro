//go:build windows
// +build windows

/*
ID: 9d110cb3-5f4b-4c9a-b9f5-53f0a1707ae5
NAME: Potential Credential Access via Trusted Developer Utility
CREATED: 2024-05-21
scenario: MSBuild loads DLLs associated with credential management
*/

package main

import (
	_ "embed"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)


/*
simulate execution of MSBuild to load DLL for credential access
*/
var supported = map[string][]string{
	"windows": {
		"powershell.exe", "-Command", "Start-Process msbuild.exe -ArgumentList '/t:rebuild' -NoNewWindow -Wait; Add-Type -AssemblyName System.Web; [System.Web.Security.Membership]::GeneratePassword(10,2)",
	}
}

func test() {
	println("[+] Attempting to execute MSBuild to load credential management DLLs")

	command := supported[runtime.GOOS]
	_, err := Endpoint.Shell(command)
	if err != nil {
		println("[+] Execution was prevented")
		Endpoint.Stop(100)
		return
	}

	println("[-] MSBuild execution was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}