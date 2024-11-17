//go:build windows
// +build windows

/*
ID: 10d1d07c-1301-4fed-b584-eb0878a74dc7
NAME: Suspicious Kernel Mode Address Manipulation
CREATED: 2024-07-02
scenario: call API to modify a kernel mode address from a user mode process. This may indicate a successful
vulnerability exploitation for privilege escalation.
*/
package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	Endpoint "github.com/preludeorg/test/endpoint"
	"golang.org/x/sys/windows"
)

func main() {
	Endpoint.Say("[+] Starting Suspicious Kernel Mode Address Manipulation VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	// Attempt to allocate and modify memory in a kernel mode address range
	kernelAddress := uintptr(0x1000000000000) // Example kernel mode address
	size := uintptr(1024)                     // Memory size
	oldProtect := uint32(0)
	newProtect := windows.PAGE_EXECUTE_READWRITE

	// Allocate memory at the kernel mode address
	addr, err := windows.VirtualAlloc(kernelAddress, size, windows.MEM_COMMIT|windows.MEM_RESERVE, newProtect)
	if err != nil || addr != kernelAddress {
		Endpoint.Say(fmt.Sprintf("[-] Failed to allocate memory at kernel mode address: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] Successfully allocated memory at kernel mode address")

	// Modify memory protection
	err = windows.VirtualProtect(kernelAddress, size, newProtect, &oldProtect)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to change memory protection at kernel mode address: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	Endpoint.Say("[+] Successfully changed memory protection at kernel mode address")

	// Write to the kernel mode address
	data := []byte{0x90, 0x90, 0x90, 0x90} // NOP instructions
	written := uint32(0)
	err = windows.WriteProcessMemory(windows.CurrentProcess(), kernelAddress, &data[0], uintptr(len(data)), &written)
	if err != nil || written != uint32(len(data)) {
		Endpoint.Say(fmt.Sprintf("[-] Failed to write to kernel mode address: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] Successfully wrote to kernel mode address")
	Endpoint.Stop(101) // UNPROTECTED: Malicious behavior not blocked
}
func cleanup() {
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}