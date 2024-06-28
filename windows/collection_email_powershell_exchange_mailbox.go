//go:build windows
// +build windows

/*
ID: 6aace640-e631-4870-ba8e-5fdda09325db
NAME: Exporting Exchange Mailbox via PowerShell
CREATED: 2024-06-28
scenario: Exchange PowerShell cmdlet `New-MailBoxExportRequest` used to export contents of mailbox to `.pst`
sensitive information collection
*/

package main

import (
	- "embed"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"powershell.exe", "-Command", `New-MailboxExportRequest -Mailbox user@example.com -FilePath \\server\share\export.pst`},
}

func test() {
	println("[+] initiating mailbox export using PowerShell cmdlet")

	command := supported[runtime.GOOS]
	_, err := Endpoint.Shell(command)
	if err != nil {
		println("[+] execution prevented")
		Endpoint.Stop(100)
		return
	}
	println ("[-] mailbox export not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}