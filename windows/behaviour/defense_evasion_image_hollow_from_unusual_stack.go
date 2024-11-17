//go:build windows
// +build windows

/*
ID: 446e61bf-8370-45df-88ab-7b213ee653db
NAME: Image Hollow from Unusual Stack
CREATED: 2024-06-28
scenario: modifying content of loaded module from suspicious call stack
attempt to inject code using module stomping or DLL hollowing
overwriting content of legit DLL with malicious code
*/
package main

import (
	_ "embed"
	"os"
	"os/exec"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var legitimateDLL []byte
var maliciousDLL []byte

/*
write legitimate.dll to temp location
overwrite legit dll with malicious.dll [hollowing]
execute modified DLL
check injection
*/
func test() {
	Endpoint.Say("testing...")

	legitPath := Endpoint.Pwd("legitimate.dll")
	Endpoint.Write(legitPath, legitimateDLL)
	defer cleanup(legitPath)

	Endpoint.Wait(5*time.Second)

	Endpoint.Say("overwriting...")
	Endpoint.Write(legitPath, maliciousDLL)

	cmd := exec.Command("rundll32.exe", legitPath, "DllMain")
	err := cmd.Start()
	if err != nil {
		Endpoint.Say("error executing" + err.Error())
		Endpoint.Stop(1)
		return
	}

	Endpoint.Wait(5*time.Second)

	// check for injection
	if cmd.Process != nil {
		Endpoint.Say("injection not blocked")
		Endpoint.Stop(101) // unprotected
	} else {
		Endpoint.Say("injection blocked")
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
