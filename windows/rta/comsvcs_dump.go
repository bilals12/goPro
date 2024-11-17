//go:build windows
// +build windows

/*
ID: 413cf7ef-0fad-46fd-ab67-e94c4e3e0f0b
NAME: Memory Dump via Comsvcs
CREATED: 2024-06-29
scenario: Invoke comsvcs.dll with rundll32.exe to mimic creating a process MiniDump
*/
package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting Memory Dump via Comsvcs VST")
	Endpoint.Start(test, cleanup)
}

/*
create memory dump via comsvcs.dll
check if dump file exists
*/
func test() {
	// form command
	cmd := exec.Command("powershell.exe", "-c", "rundll32.exe", "C:\\Windows\\System32\\comsvcs.dll", "MiniDump", fmt.Sprintf("%d dump.bin full", os.Getpid()))

	// execute command
	out, err := cmd.CombinedOutput()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("failed to execute command: %s", string(out)))
		Endpoint.Say(1) // error
	}

	Endpoint.Say(fmt.Sprintf("successfully executed command: %s", string(out)))

	// protection?
	if strings.Contains(string(out), "Access Denied") {
		Endpoint.Say("process execution blocked")
		Endpoint.Stop(126) // PROTECTED
	}

	// delay
	time.Sleep(1*time.Second)

	// check if dump file exists
	if _, err := os.Stat("dump.bin"); os.IsNotExist(err) {
		Endpoint.Say("dump file not created")
		Endpoint.Stop(100) // PROTECTED
	}
}

func cleanup() {
	// remove created file
	if err := os.Remove("dump.bin"); err != nil {
		Endpoint.Say(fmt.Sprintf("failed to remove file: %s", err))
		Endpoint.Stop(103) // ERROR: cleanup failed
	}
	Endpoint.Say("cleanup completed")
	Endpoint.Stop(100) // PROTECTED
}