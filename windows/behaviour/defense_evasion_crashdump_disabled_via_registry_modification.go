//go:build windows
// +build windows

/*
ID: 77ca3fcc-f607-45e0-837e-e4173e4ffc2a
NAME: CrashDump Disabled via Registry Modification
CREATED: 2024-06-
scenario: malware using kernel mode component may disable memory crashdump to limit exposure
*/
package main

import (
	"golang.org/x/sys/windows/registry"
	Endpoint "github.com/preludeorg/test/endpoint"
)


/*
open registry key `SYSTEM\CurrentControlSet\Control\CrashControl` with write access
modify `CrashDumpEnabled` reg value to 0 [disable crashdump]
*/
func test() {
	Endpoint.Say("testing...")

	// modify reg to disable crash dump
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\CrashControl`, registry.SET_VALUE)
	if err != nil {
		Endpoint.Say("error opening registry key: "  + err.Error())
		Endpoint.Stop(1)
		return
	}
	defer key.Close()

	err = key.SetDWordValue("CrashDumpEnabled", 0)
	if err != nil {
		Endpoint.Say("error setting registry value: " + err.Error())
		Endpoint.Stop(1)
		return
	}

	Endpoint.Say("registry value set to disable crash dump")

	// verify
	value, _, err := key.GetIntegerValue("CrashDumpEnabled")
	if err != nil {
		Endpoint.Say("error reading registry value: " + err.Error())
		Endpoint.Stop(1)
		return
	}

	if value == 0 {
		Endpoint.Say("CrashDumpEnabled set to 0")
		Endpoint.Stop(101) // unprotected
	} else {
		Endpoint.Say("CrashDumpEnabled is not set to 0")
		Endpoint.Stop(100) // protected
	}
}

func cleanup() {
	Endpoint.Say("cleaning up...")
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\CrashControl`, registry.SET_VALUE)
	if err == nil {
		defer key.Close()
		key.SetDWordValue("CrashDumpEnabled", 1)
	}
}

func main() {
	Endpoint.Start(test, cleanup)
}