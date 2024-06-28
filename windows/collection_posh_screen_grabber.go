//go:build windows
// +build windows

/*
ID: 959a7353-1129-4aa7-9084-30746b256a70
NAME: PowerShell Suspicious Script with Screenshot Capabilities
CREATED: 2024-06-28
scenario: PowerShell scripts used to take screenshots [RATs]
*/

package main

import (
	_ "embed"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

/*
screenshot using `System.Drawing` + `System.Windows.Forms`
1. load `System.Drawing` assembly [graphics]
2. load `System.Windows.Forms` assembly [forms + screen dimensions]
3. create new bitmap object with dimensions of primary screen
4. create graphics object from bitmap
5. copy screen content to bitmap
6. save bitmap as PNG to specified location
*/

var supported map[string][]string{
	"windows": {"powershell.exe", "-Command", `
Add-Type -AssemblyName System.Drawing 
Add-Type -AssemblyName System.Windows.Forms 
$bitmap = New-Object Drawing.Bitmap ([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width, [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height) 
$graphics = [Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen(0, 0, 0, 0, $bitmap.Size)
$bitmap.Save("C:\\Users\\Public\\screenshot.png")
`}
}

func test() {
	println("[+] initiating script with screenshots")
	command := supported[runtime.GOOS]
	_, err := Endpoint.Shell(command)
	if err != nil {
		println("[+] execution prevented")
		Endpoint.Stop(100)
		return
	}

	println("[-] screenshot script not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}