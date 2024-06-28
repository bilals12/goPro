//go:build windows
// +build windows

/*
ID: 8f242ffb-b191-4803-90ec-0f19942e17fd
NAME: Potential ADIDNS Poisoning via Wildcard Record Creation
CREATED: 2024-05-21
scenario: creating wildcard DNS records in Active Directory Integrated DNS
redirect traffic, enable AitM, manipulate traffic
*/

package main

import (
	_ "embed"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {
		"powershell.exe", "-Command", "Add-DnsServerResourceRecord -ZoneName example.com -Name '*' -RecordType A -AllowUpdateAny -IPv4Address 192.168.0.1",
	},
}

func test() {
	println("[+] Attempting to create a wildcard DNS record")

	command := supported[runtime.GOOS]
	_, err := Endpoint.Shell(command)
	if err != nil {
		println("[+] Execution was prevented")
		Endpoint.Stop(100)
		return
	}

	println("[-] Wildcard DNS record creation was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}