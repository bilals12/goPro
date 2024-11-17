//go:build windows
// +build windows

/*
ID: cb5fdbe3-84fa-4277-a967-1ffc0e8d3d25
NAME: Scheduled Task Creation by an Unusual Process
CREATED: 2024-06-29
scenario: creation of scheduled task by unusual process [script interpreters, unsigned executables]
*/
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting Scheduled Task Creation by an Unusual Process VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	// commands that simulate scheduled task creation by various processes
	commands := []string{
		"schtasks.exe /create /tn test_task /tr calc.exe /sc daily /f",
	}

	initialAccessProcesses := []string{
		"wscript.exe",
		"cscript.exe",
		"regsvr32.exe",
		"mshta.exe",
		"rundll32.exe",
		"vbc.exe",
		"msbuild.exe",
		"wmic.exe",
		"cmstp.exe",
		"RegAsm.exe",
		"installutil.exe",
		"RegSvcs.exe",
		"msxsl.exe",
		"xwizard.exe",
		"csc.exe",
		"winword.exe",
		"excel.exe",
		"powerpnt.exe",
		"powershell.exe",
	}

	for _, process := range initialAccessProcesses {
		for _, command := range commands {
			// initial access process
			processCmd := exec.Command("cmd.exe", "/C", fmt.Sprintf("start /B %s", process))
			err := processCmd.Start()
			if err != nil {
				Endpoint.Say(fmt.Sprintf("failed to start initial access process: %s", process))
				Endpoint.Stop(1) // ERROR
			}
			time.Sleep(2*time.Second)

			// check if we can execute commands
			if !Endpoint.IsAvailable("schtasks.exe") {
				Endpoint.Say("execution not available")
				Endpoint.Stop(126)
			}

			// execute scheduled task creation command
			out, err := exec.Command("cmd.exe", "/C", command).CombinedOutput()
			if err != nil {
				Endpoint.Say(fmt.Sprintf("failed to execute command: %s", string(out)))
				Endpoint.Stop(1) // ERROR
			}

			Endpoint.Say(fmt.Sprintf("successfully executed command: %s with initial access process: %s", command, process))

			if strings.Contains(string(out), "Access Denied") {
				Endpoint.Say("execution blocked")
				Endpoint.Stop(126) // PROTECTED
			}
		}
	}

	// execute unsigned/untrusted executable
	untrustedCmd := exec.Command("cmd.exe", "/C", "schtasks.exe /create /tn test_task_untrusted /tr calc.exe /sc daily /f")
	untrustedCmdOut, untrustedErr := untrustedCmd.CombinedOutput()
	if untrustedErr != nil {
		Endpoint.Say(fmt.Sprintf("failed to execute command: %s", string(untrustedCmdOut)))
		Endpoint.Stop(1)
	}
	Endpoint.Say("successfully executed untrusted command")

	// execution from commonly abused path
	abusedPathCmd := exec.Command("cmd.exe", "/C", "schtasks.exe /create /tn test_task_abused_path /tr calc.exe /sc daily /f")
	abusedPathCmdOut, abusedPathErr := abusedPathCmd.CombinedOutput()
	if abusedPathErr != nil {
		Endpoint.Say(fmt.Sprintf("failed to execute abused path command: %s", string(abusedPathCmdOut))
		Endpoint.Stop(1)
	}
	Endpoint.Say("successfully executed abused path command")

	// execution from mounted device
	mountedDeviceCmd := exec.Command("cmd.exe", "/C", "schtasks.exe /create /tn test_task_mounted_device /tr calc.exe /sc daily /f")
	mountedDeviceCmdOut, mountedDeviceErr := mountedDeviceCmd.CombinedOutput()
	if mountedDeviceErr != nil {
		Endpoint.Say(fmt.Sprintf("failed to execute mounted device command: %s"))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] Successfully executed mounted device command")

	Endpoint.Say("[+] Successfully executed all commands")
	Endpoint.Stop(101) // UNPROTECTED
}

func cleanup() {
	// Clean up any created files or artifacts
	exec.Command("cmd.exe", "/C", "schtasks.exe /delete /tn test_task /f").Run()
	exec.Command("cmd.exe", "/C", "schtasks.exe /delete /tn test_task_untrusted /f").Run()
	exec.Command("cmd.exe", "/C", "schtasks.exe /delete /tn test_task_abused_path /f").Run()
	exec.Command("cmd.exe", "/C", "schtasks.exe /delete /tn test_task_mounted_device /f").Run()
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}
