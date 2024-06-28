//go:build windows
// +build windows

/*
ID: 2f2f4939-0b34-40c2-a0a3-844eb7889f43
NAME: PowerShell Suspicious Script with Audio Capture Capabilities
CREATED: 2024-06-28
scenario: powershell scripts used to record audio from victim's computer [post-ex]
*/

package main

import (
	_ "embed"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"powershell.exe", "-Command", `Add-Type -TypeDefinition @"
	using System;
	using System.Runtime.InteropServices;

	public class Audio {
		[DllImport("winmm.dll", EntryPoint = "waveInGetNumDevs")]
		public status extern uint waveInGetNumDevs();
		[DllImport("winmm.dll", EntryPoint = "mciSendStringA")]
		public static extern int mciSendString(string command, StringBuilder buffer, int bufferSize, IntPtr hwndCallback);
	}
	"@; [Audio]::waveInGetNumDevs(); [Audio]::mciSendString("open new type waveaudio alias capture", $null, 0, [IntPtr]::Zero; [Audio]::mciSendString("record capture", $null, 0, [IntPtr]::Zero))`},
}

func test() {
	println("[+] Initiating PowerShell script with audio capture capabilities")

	command := supported[runtime.GOOS]
	_, err := Endpoint.Shell(command)
	if err != nil {
		println("[+] Execution was prevented")
		Endpoint.Stop(100)
		return
	}

	println("[-] Audio capture script was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}