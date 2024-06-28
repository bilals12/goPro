//go:build windows
// +build windows

/*
ID: 87c97865-fdaa-48b2-bfa6-67bed7cf56ef
NAME: DLL Hijack via Masquerading as Microsoft Native Libraries
CREATED: 2024-05-21
scenario: process loads DLL normally in `System32` or `SysWOW64` from unusual path
attackers side-load malicious DLLs
exclude false-positives by looking at low occurrences
*/

package main

import (
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

/*
use `notepad.exe` to load malicious DLL
simulate DLL hijacking by placing DLL in `Temp` and modifying `PATH`
*/

var supported = map[string][]string{
	"windows": {
		"C:\\Windows\\System32\\notepad.exe",
	},
}

func createMaliciousDLL(path string) {
	dllContent := []byte{ /* binary content */ }
	err := os.WriteFile(path, dllContent, 0644)
	if err != nil {
		println("[-] failed to create malicious DLL")
		Endpoint.Stop(102)
	}
}

func test() {
	println("[+] attempting to detect DLL hijack via NT libraries")

	command := supported[runtime.GOOS]
	// creating malicious DLL
	dllPath := filepath.Join(os.TempDir(), "msvcrt.dll")
	createMaliciousDLL(dllPath)

	// load malicious DLL using trusted process
	cmd := exec.Command(command[0])
	cmd.Env = append(os.Environ(), "PATH="+os.TempDir())
	err := cmd.Run()
	if err != nil {
		println("[-] failed to execute")
		Endpoint.Stop(101)
		return
	}

	// clean up
	err = os.Remove(dllPath)
	if err != nil {
		println("[-] failed to remove")
	}

	println("[+] successfully detected DLL hijack")
	Endpoint.Stop(100)
}