//go:build windows
// +build windows

/*
ID: 16a52c14-7883-47af-8745-9357803f0d4c
NAME: Component Object Model Hijacking
CREATED: 2024-05-21
scenario: COM hijacking is modifying registry to replace legit COM references with malicious ones
*/

package main

import (
"os/exec"
"runtime"
"time"
"golang.org/x/sys/windows/registry"
Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"cmd.exe", "/C", "reg add HKCU\Software\Classes\CLSID\{{00021401-0000-0000-C000-000000000046}\InprocServer32 /ve /t REG_SZ /d C:\Windows\System32\scrobj.dll /f"},
}

func test() {
	// simulate COM hijack by modifying reg
	println("[+] simulating...")
	command := supported[runtime.GOOS]
	cmd := exec.Command(command[0], command[1:]...)
	err := cmd.Start()
	if err != nil {
		println("[+] execution blocked!")
		Endpoint.Stop(126)
		return
	}
	time.Sleep(3 * time.Second)

	// check if modification succeeded
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Classes\CLSID\{00021401-0000-0000-C000-000000000046}\InprocServer32`, registry.QUERY_VALUE)
	if err != nil {
		println("[+] Registry modification was blocked")
		Endpoint.Stop(126)
		return
	}
	defer key.Close()

	val, _, err := key.GetStringValue("")
	if err != nil || val != `C:\Windows\System32\scrobj.dll` {
		println("[+] Registry modification was blocked or tampered")
		Endpoint.Stop(126)
		return
	}
	println("[-] COM hijacking registry modification was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}
