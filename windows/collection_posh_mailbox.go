//go:build windows
// +build windows

/*
ID: a2d04374-187c-4fd9-b513-3ad4e7fdd67a
NAME: PowerShell Mailbox Collection Script
CREATED: 2024-06-28
scenario: PowerShell script used to collect data from mailbox
*/

package main

import (
	_ "embed"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

/*
1. load outlook interop assembly to allow interaction with outlook
2. create new instance of outlook app
3. get MAPI namespace [provides access to outlook folders]
4. access default inbox folder
5. iterate thru each email + output subject
*/

var supported = map[string][]string{
	"windows": {"powershell.exe", "-Command", `
Add-Type -AssemblyName "Microsoft.Office.Interop.Outlook"
$outlook = New-Object -ComObject Outlook.Application
$namespace = $outlook.GetNamespace("MAPI")
$inbox = $namespace.GetDefaultFolder(Microsoft.Outlook.Interop.Outlook.OlDefaultFolders]::olFolderInbox)
$messages = $inbox.Items
$messages | ForEach-Object {$_.Subject }
`},
}

func test() {
	println("[+] initiating powershell mailbox collection script")
	command := supported[runtime.GOOS]
	_, err := Endpoint.Shell(command)
	if err != nil {
		println("[+] execution prevented")
		Endpoint.Stop(100)
		return
	}
	println("[-] mailbox collection script not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}