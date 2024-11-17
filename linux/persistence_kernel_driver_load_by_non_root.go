//go:build linux
// +build linux

/*
ID: ba81c182-4287-489d-af4d-8ae834b06040
NAME: Kernel Driver Load by non-root User
CREATED: 2024-01-10
scenario: check if process is running as root user

*/

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

// dummy kernel module data 
var dummyModule []byte = []byte("dummyModule content")

func loadKernelModuleAsNonRoot() error {
	// switch to non-root user
	uid := os.Getuid()
	if uid == 0 {
		// drop privs to non-root user
		err := syscall.Setuid(1000) // assuming 1000 is non-root
		if err != nil {
			return fmt.Errorf("failed to drop privs: %v", err)
		}
	}

	// dummy kernel module path
	cmd := exec.Command("insmod", "/path/to/module.ko")
	return cmd.Run()
}

func test() {
	fmt.Println("[+] Attempting to load a kernel module as non-root user")
	err := loadKernelModuleAsNonRoot()
	if err != nil {
		fmt.Println("[-] Failed to load the kernel module:", err)
		Endpoint.Stop(101) // Unprotected: Test completed but should have been blocked
		return
	}

	// Verify if the module was successfully loaded
	time.Sleep(3 * time.Second) // Allow some time for the module to load
	cmd := exec.Command("lsmod")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("[-] Error while checking loaded modules:", err)
		Endpoint.Stop(256) // Error: Unexpected execution error
		return
	}

	if contains(string(output), "module_name") {
		fmt.Println("[-] Kernel module loaded successfully by non-root user")
		Endpoint.Stop(101) // Unprotected: The system defenses did not stop or block this test as expected
	} else {
		fmt.Println("[+] Kernel module was blocked from loading by non-root user")
		Endpoint.Stop(9) // Protected: The test process was force killed (expected result)
	}
}

func contains(output, moduleName string) bool {
	return strings.Contains(output, moduleName)
}

func main() {
	Endpoint.Start(test)
}