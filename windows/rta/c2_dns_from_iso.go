//go:build windows
// +build windows

/*
ID: ba802fb2-f183-420e-947m-da5ce0235d123
NAME: Suspicious DNS Query from Mounted Virtual Disk
CREATED: 2024-06-29
scenario: mount ISO, execute program, perform DNS queries
*/
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting Suspicious DNS Query from Mounted Virtual Disk VST")
	Endpoint.Start(test, cleanup)
}

/*
define paths for .iso and .ps script
check if they exist
chceck if powershell is available
execute PS command for each domain
*/

func test {
	isoPath := "C:\\path\\to\\iso.iso" // customize
	psScriptPath := "C:\\path\\to\\ps1.ps1" // customize
	proc := "ping.exe"
	domains := []string{"abc.xyz", "content.dropboxapi.com", "x1.c.lencr.org"}

	// check if iso and .ps1 script exist
	if _, err := os.Stat(isoPath); os.IsNotExist(err) {
		Endpoint.Say(fmt.Sprintf("ISO not found: %s", isoPath))
		Endpoint.Stop(1) // error
	}
	if _, err := os.Stat(psScriptPath); os.IsNotExist(err) {
		Endpoint.Say(fmt.Sprintf("powershell script not found: %s", psScriptPath))
		Endpoint.Stop(1) // error
	}

	for _, domain := range domains {
		// construct powershell command
		command := fmt.Sprintf("powershell.exe -ExecutionPolicy Bypass -File %s -ISOFile %s -cmdline %s", psScriptPath, isoPath, proc, domain)

		// protection?
		if !Endpoint.IsAvailable("powershell.exe") {
			Endpoint.Say("powershell not available")
			Endpoint.Stop(126) // PROTECTED: access denied
		}

		// execute command
		out, err := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", psScriptPath, "-ISOFile", isoPath, "-procname", proc, "-cmdline", domain).CombinedOutput()
		if err != nil {
			Endpoint.Say(fmt.Sprintf("failed to execute command: %s", string(out)))
			Endpoint.Stop(1) // error
		}

		Endpoint.Say(fmt.Sprintf("successfully executed command for domain: %s", domain))

		// protection?
		if strings.Contains(string(out), "Access Denied") {
			Endpoint.Say("process execution blocked")
			Endpoint.Stop(126)
		}
	}
	Endpoint.Stop(101) // UNPROTECTED
}

func cleanup() {
	isoPath := "C:\\path\\to\\ping_dns_from_iso.iso"  // Adjust this path as needed
	psScriptPath := "C:\\path\\to\\ExecFromISOFile.ps1" // Adjust this path as needed

	// Clean up any mounted ISO or executed processes
	Endpoint.Say("[+] Starting cleanup")
	exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", fmt.Sprintf("Dismount-DiskImage -ImagePath %s", isoPath)).Run()
	exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", fmt.Sprintf("Stop-Process -Name %s", "ping")).Run()

	// Remove any temporary files or directories if needed
	Endpoint.Remove(isoPath)
	Endpoint.Remove(psScriptPath)

	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}