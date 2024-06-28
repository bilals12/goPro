//go:build windows
// +build windows

/*
ID: 45d273fb-1dca-457d-9855-bcb302180c21
NAME: Encrypting Files with WinRar or 7z
CREATED: 2024-06-28
scenario: using winrar/7z to encrypt data before exfil
*/
package main

import (
	_ "embed"
	"os/exec"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"cmd.exe", "/C", "7z.exe a -pMySecretPassword archive.7z *", 
},
}

func test() {
	println("[+] initiating file encryption with 7z")
	command := supported[runtime.GOOS]
	cmd := exec.Command(command[0], command[1:]...)
	err := cmd.Run()
	if err != nil {
		println("[+] execution prevented")
		Endpoint.Stop(100)
		return
	}
	println("[-] File encryption was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}
