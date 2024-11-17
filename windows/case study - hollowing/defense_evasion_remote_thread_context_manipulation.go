//go:build windows
// +build windows

/*
ID: c456266f-e920-4acb-9b32-711fa7b94ca5
NAME: Remote Thread Context Manipulation
CREATED: 2024-07-02
scenario: potential remote process manipulation using SetThreadContext API. This may indicate an attempt to inject code
or debug a remote process.
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
	Endpoint.Say("[+] Starting Remote Thread Context Manipulation VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	// Start a target process to work with
	cmd := exec.Command("notepad.exe")
	err := cmd.Start()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to start process: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	defer cmd.Process.Kill()

	// Get handle to the target process
	procHandle, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, uint32(cmd.Process.Pid))
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to get process handle: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// main thread of target proc
	threadHandle, err := getMainThreadHandle(cmd.Process.Pid)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to get main thread handle: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// manipulating thread context
	var context windows.Context
	context.ContextFlags = windows.CONTEXT_FULL
	err = windows.GetThreadContext(threadHandle, &context)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to get thread context: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// change thread context: change instruction pointer to shellcode address
	context.Rip = uintptr(unsafe.Pointer(&dummyShellcode[0]))
	err = windows.SetThreadContext(threadHandle, &context)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to set thread context: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	Endpoint.Say("[+] Remote thread context manipulation executed successfully")
	Endpoint.Stop(101) // UNPROTECTED: Malicious behavior not blocked
}

func getMainThreadHandle(pid int) (windows.Handle, error) {
	var snapshot windows.Handle
	var entry windows.ThreadEntry32
	// take snapshot of specified processes
	// 
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	entry.Size = uint32(unsafe.Sizeof(entry))
	// retrieve info about first thread of process from snapshot
	err = windows.Thread32First(snapshot, &entry)
	if err != nil {
		return 0, err
	}

	for {
		if entry.OwnerProcessID == uint32(pid) {
			threadHandle, err := windows.OpenThread(windows.THREAD_ALL_ACCESS, false, entry.ThreadID)
			if err != nil {
				return 0, err
			}
			return threadHandle, nil
		}
		err = windows.Thread32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}
	return 0, fmt.Errorf("no main thread found for process %d", pid)
}

var dummyShellcode = []byte {
	0x90, 0x90, 0x90, 0x90
}

func cleanup() {
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}