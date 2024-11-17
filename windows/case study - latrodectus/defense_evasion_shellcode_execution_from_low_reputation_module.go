//go:build windows
// +build windows

/*
ID: 9fda6a38-3822-45b6-b621-02f750e8cf0d
NAME: Shellcode Execution from Low Reputation Module
CREATED: 2024-07-01
scenario: attempt to allocate/shellcode from module with low/unknown reputation
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
	Endpoint.Say("[+] Starting Shellcode Execution from Low Reputation Module VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	executeCommand := func(command string) {
		if !Endpoint.IsAvailable("cmd.exe") {
			Endpoint.Say("command execution not available")
			Endpoint.Stop(126) //PROTECTED
		}

		out, err := exec.Command("cmd.exe", "/C", command).CombinedOutput()
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

	// loading dll with low/unknown rep
	dllPath := "C:\\Users\\Public\\lowrep.dll"
	executeCommand(fmt.Sprintf("powershell.exe -Command New-Item -Path %s -ItemType File", dllPath))

	// process execution [loading DLL + executing shellcode]
	commands := []string{
		fmt.Sprintf("powershell.exe -Command Invoke-Expression -Command {Add-Type -TypeDefinition @\"using System;using System.Runtime.InteropServices;public class Win32{[DllImport(\\\"%s\\\", SetLastError=true)]public static extern IntPtr LoadLibrary(string lpLibFileName);[DllImport(\\\"%s\\\", SetLastError=true)]public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);[DllImport(\\\"kernel32.dll\\\")]public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);public delegate IntPtr GetShellcode();[DllImport(\\\"kernel32.dll\\\")]public static extern IntPtr CreateThread(IntPtr, lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);public static void Main(){IntPtr hModule = LoadLibrary(\\\"%s\\\");IntPtr procAddr = GetProcAddress(hModule, \\\"GetShellcode\\\");GetShellcode shellcode = (GetShellcode)Marshal.GetDelegateForFunctionPointer(procAddr, typeof(GetShellcode));IntPtr addr = shellcode();uint oldProtect;VirtualProtect(addr, (UIntPtr)0x1000, 0x40, out oldProtect);CreateThread(IntPtr.Zero, UIntPtr.Zero, addr, IntPtr.Zero, 0, out _);}}\"@;[Win32]::Main()}", dllPath, dllPath, dllPath),
	}
	for _, command := range commands {
		executeCommand(command)
	}
	// exclusions
	exclusionCommands := []string{
		"powershell.exe -Command Invoke-Expression -Command {Start-Process rundll32.exe -ArgumentList '--no-sandbox'}",
	}
	for _, command := range exclusionCommands {
		executeCommand(command)
	}
	Endpoint.Stop(101) // UNPROTECTED
}
func cleanup() {
	// Remove the created low reputation DLL file
	os.Remove("C:\\Users\\Public\\lowrep.dll")

	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}