//go:build windows
// +build windows

/*
ID: 6bda13bc-f952-4353-9a97-2c7a38b21010
NAME: Disabling Hypervisor-protected Code Integrity via Registry
CREATED: 2024-06-28
scenario: disabling HVCI can allow unsigned code to be executed
*/

package main

import (
	"golang.org/x/sys/windows/registry"
	Endpoint "github.com/preludeorg/test/endpoint"
)

/*
open registry key with write access
modify value to 0 [disabling HVCI]
verify
*/
func test() {
	Endpoint.Say("testing...")

	// modifying registry to disable HVCI
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`, registry.SET_VALUE)
	if err != nil {
		Endpoint.Say("error opening key: " + err.Error())
		Endpoint.Stop(1)
		return
	}
	defer key.Close()

	err = key.SetDWordValue("Enabled", 0)
	if err != nil {
		Endpoint.Say("error setting value: " + err.Error())
		Endpoint.Stop(1)
		return
	}

	Endpoint.Say("value set to disable HVCI")

	// verify
	value, _, err := key.GetIntegerValue("Enabled")
	if err != nil {
		Endpoint.Say("error reading value: " + err.Error())
		Endpoint.Stop(1)
		return
	}

	if value == 0 {
		Endpoint.Say("HVCI set to 0")
		Endpoint.Stop(101) // unprotected
	} else {
		Endpoint.Say("HVCI still enabled")
		Endpoint.Stop(100) // protected
	}
}

func cleanup() {
	Endpoint.Say("cleaning up")
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`, registry.SET_VALUE)
	if err == nil {
		defer key.Close()
		key.SetDWordValue("Enabled", 1)
	}
}

func main() {
	Endpoint.Start(test, cleanup)
}