//go:build windows
// +build windows

/*
ID: 6e176443-7a9a-4c22-a239-164812cf961c
NAME: Executable Heap Allocation by Unsigned Module
CREATED: 2024-06-28
scenario: creating heap memory allocation with permission [`HEAP_CREATE_ENABLE_EXECUTE` option]
indicates preparing for shellcode injection evading security that monitors VirtualAlloc API calls
*/
package main

import (
	_ "embed"
	Endpoint "github.com/preludeorg/test/endpoint"
	"os/exec"
	"syscall"
	"unsafe"
)

var unsignedDLL []byte

/*
write embedded `unsigned.dll` to temp location
use `rundll32.exe` to load unsigned DLL in suspended state
use `HeapCreate` + `HeapAlloc` from `kernel32.dll` to create heap with X permissions + allocate memory within heap
write shellcode [`0x90` NOPs] into allocated memory to simulate executable heap allocation
verify
*/
func test() {
	Endpoint.Say("testing...")

	dllPath := Endpoint.Pwd("unsigned.dll")
	Endpoint.Write(dllPath, unsignedDLL)

	cmd := exec.Command("rundll32.exe", dllPath+",DllMain")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_SUSPENDED}
	err := cmd.Start()
	if err != nil {
		Endpoint.Say("error loading DLL " err.Error())
		Endpoint.Stop(1)
		return
	}
	// allocate memory
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	heapCreate := kernel32.NewProc("HeapCreate")
	heapAlloc := kernel32.NewProc("HeapAlloc")

	heap, _, _ := heapCreate.Call(0x00040000, 0, 0x1000)
	if heap == 0 {
		Endpoint.Say("error creating heap")
		Endpoint.Stop(1)
		return
	}
	mem, _, _ := heapAlloc.Call(heap, 0x00000008, 0x1000)
	if mem == 0 {
		Endpoint.Say("error allocating memory")
		Endpoint.Stop(1)
		return
	}

	// shellcode
	shellcode := []byte{0x90, 0x90, 0x90, 0x90}
	for i, b := range shellcode {
		ptr := unsafe.Pointer(mem + uintptr(i))
		*(*byte)(ptr) = b
	}

	Endpoint.Say("heap memory allocation successful")
	Endpoint.Stop(101) // unprotected

}

func cleanup() {
	Endpoint.Say("cleaning up")
	dllPath := Endpoint.Pwd("unsigned.dll")
	Endpoint.Remove(dllPath)
}

func main() {
	Endpoint.Start(test, cleanup)
}