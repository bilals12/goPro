//go:build windows
// +build windows

/*
ID: bd2c86a0-8b61-4457-ab38-96943984e889
NAME: PowerShell Keylogging Script
CREATED: 2024-06-28
scenario: powershell scripts use Win32 API to capture keystrokes
*/
package main

import (
	_ "embed"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"powershell.exe", "-Command", `[Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms");
	$Global:Keys = @()
	$Callback = {
		Param($I, $E)
		$Global:Keys += $E.KeyCode
	}
	$Form = New-Object System.Windows.Forms.Form
	$Form.KeyPreview = $True
	$Form.Add_KeyDown($Callback)
	$Form.ShowDialog() | Out-Null
	$Form.Dispose()
	$Global:Keys`},
}

func test() {
	println("[+] Initiating PowerShell keylogging script")

	command := supported[runtime.GOOS]
	_, err := Endpoint.Shell(command)
	if err != nil {
		println("[+] Execution was prevented")
		Endpoint.Stop(100)
		return
	}

	println("[-] Keylogging script was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}