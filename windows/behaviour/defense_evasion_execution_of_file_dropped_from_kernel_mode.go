//go:build windows
// +build windows

/*
ID: 1c618d05-2cac-4979-9c85-6320fc317177
NAME: Execution of a File Dropped from Kernel Mode
CREATED: 2024-06-28
scenario: loading an untrusted executable dropped by kernel-mode code
malicious code can be executed in user-mode via existing malicious kernel drivers
*/

package main

import (
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var maliciousExe []byte

/*
write embedded `malicious.exe` to temp loc
simulate kernel mode drop
execute dropped file
verify
*/
func test() {
	Endpoint.Say("testing...")

	dropPath := Endpoint.Pwd("malicious.exe")
	Endpoint.Write(dropPath, maliciousExe)
	defer cleanup(dropPath)

	Endpoint.Wait(5*time.Second)

	cmd := exec.Command(dropPath)
	err := cmd.Start()
	if err != nil {
		Endpoint.Say("error executing " + err.Error())
		Endpoint.Stop(1)
		return
	}

	Endpoint.Wait(5*time.Second)

	if cmd.Process != nil {
		Endpoint.Say("not blocked")
		Endpoint.Stop(101) // unprotected
	} else {
		Endpoint.Say("blocked")
		Endpoint.Stop(100) // protected
	}
}

func cleanup(path string) {
	Endpoint.Say("cleaning up")
	Endpoint.Remove(path)
}

func main() {
	Endpoint.Start(test, cleanup)
}