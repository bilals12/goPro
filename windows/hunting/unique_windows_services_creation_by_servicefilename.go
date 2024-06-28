//go:build windows
// +build windows

/*
ID: ebf79207-16dc-44f8-b10c-317d4a034bad
NAME: Unique Windows Services Creation by Service File Name
CREATED: 2024-05-21
*/
package main

import (
	_ "embed"
	"os/exec"
	"strings"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {
		"C:\\Windows\\System32\\sc.exe",
	},
}

func test() {
	println("[+] attempting to create unique Windows service")

	command := supported["windows"]
	serviceName := "MyUniqueService"
	serviceBinary := "C:\\Windows\\Temp\\MyServiceBinary.exe"

	// creating a unique windows service
	cmd := exec.Command(command[0], "create", serviceName, "binPath=", serviceBinary)
	err := cmd.Run()
	if err != nil {
		print("[-] failed to create service")
		Endpoint.Stop(101)
		return
	}

	// verify service creation
	verifyCmd := exec.Command(command[0], "query", serviceName)
	output, err := verifyCmd.Output()
	if err != nil {
		println("[-] failed to query created service")
		Endpoint.Stop(102)
		return
	}

	if strings.Contains(string(output), serviceName) {
		println("[+] successfully created + verified unique service")
		// clean up
		deleteCmd := exec.Command(command[0], "delete", serviceName)
		err = deleteCmd.Run()
		if err != nil {
			println("[-] failed to delete")
		}
		Endpoint.Stop(100)
	} else {
		println("[-] service creation verification failed")
		Endpoint.Stop(103)
	}
}

func main() {
	Endpoint.Start(test)
}