//go:build windows
// +build windows

/*
ID: 6e84852e-b8a2-4158-971e-c5148d969d2a
NAME: Suspicious Execution via DotNet Remoting and Others
Suspicious ImageLoad via Windows CertOC
Suspicious ImageLoad via ODBC Driver Configuration Program
Potential Evasion via Intel GfxDownloadWrapper
CREATED: 2024-06-29
*/

package main

import (
	"fmt"
	"os"
	"os/exec"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting Suspicious Execution via DotNet Remoting and Others VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	// file paths + commands
	addinproc := "C:\\Users\\Public\\AddInProcess.exe"
	certoc := "C:\\Users\\Public\\CertOc.exe"
	odbc := "C:\\Users\\Public\\odbcconf.exe"
	gfxdwn := "C:\\Users\\Public\\GfxDownloadWrapper.exe"
	exeFile := "renamed_posh.exe"

	// copy files to location
	copyFile(exeFile, addinproc)
	copyFile(exeFile, certoc)
	copyFile(exeFile, odbc)
	copyFile(exeFile, gfxdwn)

	commands := []struct {
		path string
		args []string
	}{
		{addinproc, []string{"/guid:32a91b0f-30cd-4c75-be79-ccbd6345de99", "/pid:123"}},
		{certoc, []string{"-LoadDLL"}},
		{odbc, []string("-a", "-f")},
		{gfxdwn, []string{"run", "2", "0"}},
	}

	for _, cmd := range commands {
		if !Endpoint.IsAvailable("cmd.exe") {
			Endpoint.Say("command execution not available")
			Endpoint.Stop(126) // PROTECTED
		}

		out, err := exec.Command(cmd.path, cmd.args...).CombinedOutput()
		if err != nil {
			Endpoint.Say(fmt.Sprintf("failed to execute: %s", string(out)))
			Endpoint.Stop(1)
		}

		Endpoint.Say(fmt.Sprintf("successfully executed: %s", string(out)))

		if strings.Contains(string(out), "Access Denied") {
			Endpoint.Say("execution blocked")
			Endpoint.Stop(126) // PROTECTED
		}
	}

	Endpoint.Say("execution completed")
	Endpoint.Stop(101)
}

func copyFile(src, dest string) {
	_, err := exec.Command("cmd.exe", "/C", "copy", src, dest).Output()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to copy file: %s", err))
		Endpoint.Stop(1) // ERROR
	}
}

func cleanup() {
	files := []string{
		"C:\\Users\\Public\\AddInProcess.exe",
		"C:\\Users\\Public\\CertOc.exe",
		"C:\\Users\\Public\\odbcconf.exe",
		"C:\\Users\\Public\\GfxDownloadWrapper.exe",
	}

	for _, file := range files {
		err := os.Remove(file)
		if err != nil {
			Endpoint.Say(fmt.Sprintf("[-] Failed to remove file: %s", err))
		} else {
			Endpoint.Say(fmt.Sprintf("[+] Successfully removed file: %s", file))
		}
	}

	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}