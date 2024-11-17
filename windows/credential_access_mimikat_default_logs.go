//go:build windows
// +build windows

/*
ID: ebb200e8-adf0-43f8-a0bb-4ee5b5d852c6
NAME: Mimikatz Memssp Log File Detected
CREATED: 2024-06-29
scenario: creation of `mimilsa.log` by mimikatz `misc::memssp` module
this module injects malicious SSP to collect locally authenticated credentials (computer account pw, service creds)
*/

package main

import (
	"os"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"powershell.exe", "-Command", "New-Item -Path C:\\Windows\\System32\\mimilsa.log -ItemType File"}
}

func test() {
	Endpoint.Say("[+] simulating creation of mimikatz memssp log file")

	// create log file to simulate module activity
	file, err := os.Create("C:\\Windows\\System32\\mimilsa.log")
	if err != nil {
		Endpoint.Say("[-] failed to create mimilsa.log file: " + err.Error())
		Endpoint.Stop(101)
		return
	}
	defer file.Close()

	// add content to log file to simulate data
	_, err = file.WriteString("mimikatz memssp log data")
	if err != nil {
		Endpoint.Say("[-] failed to write to mimilsa.log file: " + err.Error())
		Endpoint.Stop(101)
		return
	}
	Endpoint.Say("[+] Mimikatz memssp log file creation simulation complete")
	Endpoint.Stop(100)
}

func main() {
	Endpoint.Start(test)
}