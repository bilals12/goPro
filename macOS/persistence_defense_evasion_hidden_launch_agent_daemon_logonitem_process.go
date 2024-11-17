//go:build darwin
// +build darwin

/*
ID: 083fa162-e790-4d85-9aeb-4fea04188adb
NAME: Suspicious Hidden Child Process of Launchd
CREATED: 2024-06-29
scenario: execution of hidden child process by `launchd`
installing a new logon item, launch agent, daemon
*/

package main

import (
	"os"
	"os/exec"
	"runtime"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"darwin": {"/sbin/launchd", "-c", "echo suspicious hidden process > /tmp/.hidden_process.txt"},
}

func test() {
	command := supported[runtime.GOOS]

	Endpoint.Say("[+] Attempting to execute a hidden child process by launchd")

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = append(os.Environ(), "PATH=/usr/bin:/bin:/usr/sbin:/sbin")
	err := cmd.Run()
	if err != nil {
		Endpoint.Say("[-] Execution of hidden child process failed: " + err.Error())
		Endpoint.Stop(101)
		return
	}
	Endpoint.Say("[+] execution completed")
	Endpoint.Stop(100)
}

func main() {
	Endpoint.Start(test)
}

