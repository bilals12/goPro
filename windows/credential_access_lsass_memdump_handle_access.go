/*
ID: 208dbe77-01ed-4954-8d44-1e5751cb20de
NAME: LSASS Memory Dump Handle Access
CREATED: 2024-06-29
scenario: accessing LSASS via access masks [SharpDump, ProcDump, Mimikatz]
*/

package main

import (
	"os"
	"os/exec"
	"runtime"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"cmd.exe", "/C", "echo Simulating LSASS memory dump handle access"},
}

func test() {
	Endpoint.Say("[+] simulating LSASS dump handle access")

	cmd := exec.Command("cmd.exe", "/C", "mimikatz.exe" \"privilege::debug\" \"log\" \"sekurlsa::minidump lsass.dmp\"")
	err := cmd.Run()
	if err != nil {
		Endpoint.Say("[-] Failed to simulate LSASS memory dump handle access: " + err.Error())
		Endpoint.Stop(101)
		return
	}

	Endpoint.Say("[+] LSASS memory dump handle access simulation complete")
	Endpoint.Stop(100)
}

func main() {
	Endpoint.Start(test)
}