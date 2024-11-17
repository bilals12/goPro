//go:build linux
// +build linux

/*
ID: 3e12a439-d002-4944-bc42-171c0dcb9b96
NAME: Kernel Driver Load
CREATED: 2023-10-
scenario: loading of LKM via syscalls [install rootkits]
detect thru auditd manager
*/

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func loadKernelModule() error {
	// dummy kernel module path
	cmd := exec.Command("insmod", "/path/to/module.ko")
	return cmd.Run()
}

func test() {
	fmt.Println("[+] attempting to load kernel module")
	err := loadKernelModule()
	if err != nil {
		fmt.Println("[-] failed to load kernel module:", err)
		Endpoint.Stop(101) // unprotected, should have been blocked
		return
	}

	// verify if module was loaded successfully
	time.Sleep(3 * time.Second) // allow time for module to load
	cmd := exec.Command("lsmod")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("[-] error while checking loaded modules:", err)
		Endpoint.Stop(256) // unexpected execution error
		return
	}

	if contains(string(output), "module_name") {
		fmt.Println("[-] kernel module loaded successfully")
		Endpoint.Stop(101) // unprotected
	} else {
		fmt.Println("[+] kernel module was blocked from loading")
		Endpoint.Stop(9) // protected, test process was successfully force killed
	}
}

func contains(output, moduleName string) bool {
	return strings.Contains(output, moduleName)
}

func main() {
	Endpoint.Start(test)
}