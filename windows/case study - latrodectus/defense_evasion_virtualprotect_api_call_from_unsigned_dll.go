//go:build windows
// +build windows

/*
ID: 8858facd-72b7-495c-831c-4d8ad12a8bf0
NAME: VirtualProtect API Call from an Unsigned DLL
CREATED: 2024-07-01
scenario: load of unsigned/untrustworthy DLL by trusted binary
followed by calling VirtualProtect API to change memory permission [WX]
execution via DLL sideloading [code injection]
*/
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting VirtualProtect API Call from an Unsigned DLL VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	executeCommand := func(command string) {
		if !Endpoint.IsAvailable("cmd.exe") {
			Endpoint.Say("[+] Command execution is not available")
			Endpoint.Stop(126) // PROTECTED: Access Denied
		}

		out, err := exec.Command("cmd.exe", "/C", command).CombinedOutput()
		if err != nil {
			Endpoint.Say(fmt.Sprintf("[-] Failed to execute command: %s", string(out)))
			Endpoint.Stop(1) // ERROR
		}

		Endpoint.Say(fmt.Sprintf("[+] Successfully executed command: %s", command))

		if strings.Contains(string(out), "Access Denied") {
			Endpoint.Say("[+] Process execution was blocked")
			Endpoint.Stop(126) // PROTECTED: Access Denied
		}
	}

	// Simulating the loading of an unsigned or untrusted DLL by a trusted binary
	dllPath := "C:\\Users\\Public\\unsigned.dll"
	executeCommand(fmt.Sprintf("powershell.exe -Command New-Item -Path %s -ItemType File", dllPath))

	// Simulate process execution that involves loading the DLL and calling VirtualProtect API
	commands := []string{
		fmt.Sprintf("powershell.exe -Command Add-Type -TypeDefinition @\"using System;using System.Runtime.InteropServices;public class Win32{[DllImport(\\\"%s\\\", SetLastError=true)]public static extern IntPtr LoadLibrary(string lpLibFileName);[DllImport(\\\"%s\\\", SetLastError=true)]public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);[DllImport(\\\"kernel32.dll\\\")]public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);public delegate IntPtr GetShellcode();[DllImport(\\\"kernel32.dll\\\")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);public static void Main(){IntPtr hModule = LoadLibrary(\\\"%s\\\");IntPtr procAddr = GetProcAddress(hModule, \\\"GetShellcode\\\");GetShellcode shellcode = (GetShellcode)Marshal.GetDelegateForFunctionPointer(procAddr, typeof(GetShellcode));IntPtr addr = shellcode();uint oldProtect;VirtualProtect(addr, (UIntPtr)0x1000, 0x40, out oldProtect);CreateThread(IntPtr.Zero, UIntPtr.Zero, addr, IntPtr.Zero, 0, out _);}}\"@;[Win32]::Main()", dllPath, dllPath, dllPath),
	}

	for _, command := range commands {
		executeCommand(command)
	}

	// Simulate exclusion conditions
	exclusionCommands := []string{
		"powershell.exe -Command Invoke-Expression -Command {Start-Process rundll32.exe -ArgumentList '--no-sandbox'}",
	}

	for _, command := range exclusionCommands {
		executeCommand(command)
	}

	Endpoint.Stop(101) // UNPROTECTED
}

func cleanup() {
	// Remove the created unsigned DLL file
	os.Remove("C:\\Users\\Public\\unsigned.dll")

	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}