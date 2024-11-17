//go:build windows
// +build windows

/*
ID: 2df08481-31db-44a8-b01d-1c0df827bddb
NAME: Adobe Hijack Persistence
CREATED: 2024-06-29
scenario: replace legit RdrCEF.exe within adobe reader dir with `cmd.exe`
executing malicious code when adobe reader launched
*/
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("beginning...")
	Endpoint.Start(test, cleanup)
}


/*
define paths for Adobe Reader dir, `RdrCEF.exe`, `cmd.exe`, backup file location
if `RdrCEF.exe` exists -> backup to specified location [create dir if not]
overwrite `RdrCEF.exe` with `cmd.exe`
*/
func test() {
	rdrCefDir := "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF"
	rdrcefExe := filepath.Join(rdrCefDir, "RdrCEF.exe")
	cmdPath := "C:\\Windows\\System32\\cmd.exe"
	backup := "C:\\Windows\\Temp\\RdrCEF_backup.exe"

	// backup the original
	if _, err := os.Stat(rdrcefExe); err == nil {
		Endpoint.Say("backing up existing RdrCEF.exe")
		if err := Endpoint.CopyFile(rdrcefExe, backup); err != nil {
			Endpoint.Say(fmt.Sprintf("failed to backup: %v", err))
			Endpoint.Stop(1) // error
		}
	} else if os.IsNotExist(err) {
		Endpoint.Say("RdrCEF.exe doesn't exist. creating directory...")
		if err := os.MkdirAll(rdrCefDir, os.ModePerm); err != nil {
			Endpoint.Say(fmt.Sprintf("failed to create directory: %v", err))
			Endpoint.Stop(1) // error
		}
	} else {
		Endpoint.Say(fmt.Sprintf("failed to check RdrCEF.exe existence: %v", err))
		Endpoint.Stop(1) // error
	}

	// check if we can write to dir
	if !Endpoint.IsWritable(rdrcefExe) {
		Endpoint.Say("write access denied")
		Endpoint.Stop(126) // PROTECTED: access denied
	}

	// overwrite RdrCEF.exe with cmd.exe
	if err := Endpoint.CopyFile(cmdPath, rdrcefExe); err != nil {
		Endpoint.Say(fmt.Sprintf("failed to copy cmd.exe to RdrCEF.exe: %v", err))
		Endpoint.Stop(1)
	}
	Endpoint.Say("successfully replaced RdrCEF.exe with cmd.exe")

	// check if file is quarantined appropriately
	if Endpoint.Quarantined(rdrcefExe, nil) {
		Endpoint.Say("RdrCEF.exe was quarantined")
		Endpoint.Stop(127) // PROTECTED: file quarantined
	}
	Endpoint.Stop(101) //UNPROTECTED

}

func cleanup() {
	rdrCefDir := "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF"
	rdrcefExe := filepath.Join(rdrCefDir, "RdrCEF.exe")
	backup := "C:\\Windows\\Temp\\RdrCEF_backup.exe"

	if _, err := os.Stat(backup); err == nil {
		Endpoint.Say("[+] Restoring backup copy")
		if err := Endpoint.CopyFile(backup, rdrcefExe); err != nil {
			Endpoint.Say(fmt.Sprintf("[-] Failed to restore backup: %v", err))
			Endpoint.Stop(1) // ERROR
		}
		if err := os.Remove(backup); err != nil {
			Endpoint.Say(fmt.Sprintf("[-] Failed to remove backup file: %v", err))
			Endpoint.Stop(1) // ERROR
		}
	} else {
		Endpoint.Say("[+] Removing created RdrCEF.exe")
		if err := os.Remove(rdrcefExe); err != nil {
			Endpoint.Say(fmt.Sprintf("[-] Failed to remove RdrCEF.exe: %v", err))
			Endpoint.Stop(1) // ERROR
		}
		if err := os.RemoveAll(rdrCefDir); err != nil {
			Endpoint.Say(fmt.Sprintf("[-] Failed to remove directory: %v", err))
			Endpoint.Stop(1) // ERROR
		}
	}

	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}

