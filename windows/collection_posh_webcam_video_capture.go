//go:build windows
// +build windows

/*
ID: eb44611f-62a8-4036-a5ef-587098be6c43
NAME: PowerShell Script with Webcam Video Capture Capabilities
CREATED: 2024-06-28
scenario: using a powershell script to capture webcam video
*/

package main

import (
	_ "embed"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

/*
record webcam video using `avicap32.dll` library
1. load `System.Windows.Forms` assembly 
2. define C# class `WebcamCapture` that uses `capCreateCaptureWindow` for webcam
3. start capture
*/

var supported = map[string][]string {
	"windows": {"powershell.exe", "-Command", `
Add-Type -AssemblyName System.Windows.Forms 
Add-Type -TypeDefinition @" 
using System;
using System.Drawing;
using System.Windows.Forms;
using System.Runtime.InteropServices;

public class WebcamCapture
{
	[DllImport("avicap32.dll", EntryPoint = "capCreateCaptureWindowA")]
	public static extern IntPtr capCreateCaptureWindow(
		string lpszWindowName, int dwStyle, int x, int y, int nWidth, int nHeight, IntPtr hWndParent, int nID);

	public void StartCapture()
	{
		IntPtr hCaptureWnd = capCreateCaptureWindow("webcam capture", 0x40000000 | 0x10000000, 0, 0, 640, 480, IntPtr.Zero, 0);
		// code here to save video
	}
}
"@
$wc = New-Object WebcamCapture 
$wc.StartCapture()
`},
}

func test() {
	println("[+] Initiating PowerShell script with webcam video capture capabilities")

	command := supported[runtime.GOOS]
	_, err := Endpoint.Shell(command)
	if err != nil {
		println("[+] Execution was prevented")
		Endpoint.Stop(100)
		return
	}

	println("[-] Webcam video capture script was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}