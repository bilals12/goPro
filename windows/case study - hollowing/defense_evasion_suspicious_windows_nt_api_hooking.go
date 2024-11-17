//go:build windows
// +build windows

/*
ID: 63f3d1c5-7e19-48db-965d-cc2a52e96650
NAME: Suspicious Windows NT API Hooking
CREATED: 2024-07-02
scenario: hook certain memory section mapping related APIs with suspicious properties. This may indicate an
attempt to evade defense leveraging API hooking.
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

var ntdll = windows.NewLazyDLL("ntdll.dll")

func main() {
	Endpoint.Say("[+] Starting Suspicious Windows NT API Hooking VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	// define NT API functions to hook
	hookAPIs := []string{
		"ZwCreateSection", "NtCreateSection", "ZwOpenSection", "NtOpenSection", "ZwClose", "NtClose", "ZwMapViewOfSection", "NtMapViewOfSection", "ZwUnmapViewOfSection", "NtUnmapViewOfSection",
	}

	// load ntdll + get addresses of APIs
	for _, api := range hookAPIs {
		proc := ntdll.NewProc(api)
		addr := proc.Addr()
		Endpoint.Say(fmt.Sprintf("[+] Address of %s: 0x%X", api, addr))
		// hook API by writing JMP instruction to custom function
		hookAPI(addr)
	}

	Endpoint.Say("hooked all specified NT APIs")
	Endpoint.Stop(101) // UNPROTECTED: Malicious behavior not blocked
}

func hookAPI(addr uintptr) {
	// JMP to custom function
	jmp := []byte{0xE9, 0x00, 0x00, 0x00, 0x00} // JMP rel32
	relAddr := uintptr(unsafe.Pointer(&customFunction)) - (addr + uintptr(len(jmp)))
	*(*uintptr)(unsafe.Pointer(&jmp[1])) = relAddr

	// write JMP to target API address
	var oldProtect uint32
	err := windows.VirtualProtect(addr, uintptr(len(jmp)), windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to change memory protection: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	_, err = windows.WriteProcessMemory(windows.CurrentProcess(), addr, &jmp[0], uintptr(len(jmp)), nil)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to write memory: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	err = windows.VirtualProtect(addr, uintptr(len(jmp)), oldProtect, &oldProtect)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to restore memory protection: %s", err))
		Endpoint.Stop(1) // ERROR
	}
}

func customFunction() {
	// Custom function to be called by the hooked APIs
	Endpoint.Say("[+] Custom function called by hooked API")
}

func cleanup() {
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}