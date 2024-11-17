//go:build windows
// +build windows

/*
ID: ab23f8a3-a1ab-4def-a8d7-403f62d3f548
NAME: VirtualProtect via ROP Gadgets
CREATED: 2024-06-28
scenario: calling VirtualProtect indirectly using ROP gadgets [trying to hide the source of the call]
*/
package main

import (
	_ "embed"
	"os"
	"os/exec"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var ropVirtualProtectExe []byte

/*
execute rop_virtualprotect.exe
check if .exe was detected/blocked
*/
func test() {
	Endpoint.Say("testing...")

	dropPath := Endpoint.Pwd("rop_virtualprotect.exe")
	Endpoint.Write(dropPath, ropVirtualProtectExe)
	defer cleanup(dropPath)

	Endpoint.Wait(5*time.Second)

	Endpoint.Say("executing...")
	cmd := exec.Command(dropPath)
	err := cmd.Start()
	if err != nil {
		Endpoint.Say("error executing!")
		Endpoint.Stop(1)
		return
	}
	Endpoint.Wait(5*time.Second)

	if cmd.Process != nil {
		Endpoint.Say("execution not blocked")
		Endpoint.Stop(101) // unprotected
	} else {
		Endpoint.Say("execution blocked")
		Endpoint.Stop(100) // protected
	}
}

func cleanup(path string) {
	Endpoint.Say("cleaning up after test")
	Endpoint.Remove(path)
}

func main() {
	Endpoint.Start(test, cleanup)
}