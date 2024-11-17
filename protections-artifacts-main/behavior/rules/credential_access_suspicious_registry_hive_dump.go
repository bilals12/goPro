//go:build windows
// +build windows

/*
ID: e7358500-1ef6-4f81-ab2d-f8da696375e8
NAME: Suspicious Registry Hive Dump
CREATED: 2023-12-19
scenario: attempt to save HKLM\SAM hive to `sam.save` using `reg save`
*/

package main

import (
	"fmt"
	Endpoint "github.com/preludeorg/test/endpoint"
	"os/exec"
	"time"
)

func test() {
	Endpoint.Say("starting test...")
	// executable exclusions
	excludedExecutables := []string{
		"?:\\Program Files\\Commvault\\ContentStore\\Base\\CLBackup.exe",
		"?:\\Program Files (x86)\\Commvault\\ContentStore\\Base\\CLBackup.exe",
		"?:\\Program Files\\VS Revo Group\\Revo Uninstaller Pro\\RevoUninPro.exe",
		"?:\\Program Files (x86)\\VS Revo Group\\Revo Uninstaller Pro\\RevoUninPro.exe",
		"?:\\Program Files (x86)\\IObit\\Advanced SystemCare\\ASC.exe",
		"?:\\Program Files\\IObit\\Advanced SystemCare\\ASC.exe",
		"?:\\Program Files\\Carbonite\\Replication\\DoubleTake.exe",
		"?:\\Program Files (x86)\\Carbonite\\Replication\\DoubleTake.exe",
	}

	currentExecutable := Endpoint.Pwd("test.exe")
	for _, exec := range excludedExecutables {
		if currentExecutable == exec {
			Endpoint.Say("test is excluded")
			Endpoint.Stop(104) // not relevant
			return
		}
	}

	dumpCommand := []string{"reg", "save", "HKLM\\SAM", "C:\\Windows\\Temp\\sam.save"}
	_, err := Endpoint.Shell(dumpCommand)
	if err != nil {
		Endpoint.Say("registry hive dump prevented")
		Endpoint.Stop(100) // protected
	}

	time.Sleep(3*time.Second)

	Endpoint.Say("hive dump completed")
	Endpoint.Stop(101) // unprotected
}

func cleanup() {
	Endpoint.Remove("C:\\Windows\\Temp\\sam.save")
}

func main() {
	Endpoint.Start(test, cleanup)
}