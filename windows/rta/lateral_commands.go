//go:build windows
// +build windows

/*
ID: 389392dc-61db-4e45-846f-099f7d289c1b
NAME: Lateral Movement Commands
CREATED: 2024-06-29
scenario: check for commands associated with lateral movement
*/
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting Lateral Movement Commands VST")
	Endpoint.Start(test, cleanup)
}

/*
define IP address of remote host [127.0.0.1]
define + execute commands [explained below]
verify
*/
func test() {
	remoteHost := "127.0.0.1"

	commands := []string{
		// creates new service on remote host named `test_service` to run `cmd.exe`
		fmt.Sprintf("sc.exe \\\\%s create test_service binPath= C:\\Windows\\System32\\cmd.exe", remoteHost),
		// reconfig `test_service` to run `ipconfig.exe` instead of `cmd.exe`
		fmt.Sprintf("sc.exe \\\\%s config test_service binPath= C:\\Windows\\System32\\ipconfig.exe", remoteHost),
		// run `net.exe` if service fails
		fmt.Sprintf("sc.exe \\\\%s failure test_service command= C:\\Windows\\System32\\net.exe", remoteHost),
		// starts `test_service` on remote host
		fmt.Sprintf("sc.exe \\\\%s start test_service", remoteHost),
		// deletes `test_service` from remote host
		fmt.Sprintf("sc.exe \\\\%s delete test_service", remoteHost),
		// uses Windows Management Instrumentation Command-line to create process on remote host to run ipconfig.exe
		fmt.Sprintf("wmic.exe /node:%s process call create ipconfig.exe", remoteHost),
		// modifies user account "vagrant" to set `passwordexpires=false`
		fmt.Sprintf("wmic.exe /node:%s path WIN32_USERACCOUNT where(name='vagrant') set passwordexpires='false'", remoteHost),
		// syncs local clock with clock on remote host
		fmt.Sprintf("net.exe time \\\\%s", remoteHost),
		// connect to `admin$` share on remote host
		fmt.Sprintf("net.exe use \\\\%s\\admin$", remoteHost),
		// disconnects `admin$` share on remote host
		fmt.Sprintf("net.exe use \\\\%s\\admin$ /delete", remoteHost),
		// connects to `c$` share [C: drive] on remote host
		fmt.Sprintf("net.exe use \\\\%s\\c$", remoteHost),
		// disconnects `c$` share on remote host
		fmt.Sprintf("net.exe use \\\\%s\\c$ /delete", remoteHost),
	}
	for _, command := range commands {
		// check if protected
		if !Endpoint.IsAvailable("cmd.exe") {
			Endpoint.Say("command execution not available")
			Endpoint.Stop(126) // PROTECTED
		}

		// execute command
		out, err := exec.Command("cmd.exe", "/C", command).CombinedOutput()
		if err != nil {
			Endpoint.Say(fmt.Sprintf("failed to execute command: %s", string(out)))
			Endpoint.Stop(1)
		}
		Endpoint.Say(fmt.Sprintf("successfully executed command: %s", command))

		// check if protected
		if strings.Contains(string(out), "Access Denied") {
			Endpoint.Say("process execution blocked")
			Endpoint.Stop(126) // PROTECTED
		}
	}
	// remote powershell execution
	// this starts WinRM [Remote Mgmt] service process
	powershellCommand := "C:\\Windows\\system32\\wsmprovhost.exe -Embedding"
	out, err := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", powershellCommand).CombinedOutput()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("failed to execute powershell command: %s", string(out)))
		Endpoint.Stop(1) // error
	}

	Endpoint.Say("successfully executed powershell command")

	// schedule task commands
	schtasksHost := remoteHost
	taskName := "test_task"

	schtaskCommands := []string{
		// deletes a scheduled task with the specified name on the remote host
		fmt.Sprintf("schtasks /s %s /delete /tn %s /f", schtasksHost, taskName),
		// creates a new scheduled task on the remote host that runs ipconfig.exe monthly on the first Sunday
		fmt.Sprintf("schtasks /s %s /create /SC MONTHLY /MO first /D SUN /tn %s /tr c:\\windows\\system32\\ipconfig.exe /f", schtasksHost, taskName),
		// runs the specified scheduled task on the remote host
		fmt.Sprintf("schtasks /s %s /run /tn %s", schtasksHost, taskName),
		// deletes the specified scheduled task on the remote host
		fmt.Sprintf("schtasks /s %s /delete /tn %s /f", schtasksHost, taskName)
	}

	for _, command := range schtaskCommands {
		// execute command
		out, err := exec.Command("cmd.exe", "/C", command).CombinedOutput()
		if err != nil {
			Endpoint.Say(fmt.Sprintf("failed to execute command: %s", string(out)))
			Endpoint.Stop(1) // error
		}
		Endpoint.Say(fmt.Sprintf("successfully executed command: %s", command))

		// protection?
		if strings.Contains(string(out), "Access Denied") {
			Endpoint.Say("process execution was blocked")
			Endpoint.Stop(126) // PROTECTED
		}
	}
	Endpoint.Stop(101) // UNPROTECTED
}

func cleanup() {
	rremoteHost := "127.0.0.1"
	commands := []string{
		fmt.Sprintf("sc.exe \\\\%s delete test_service", remoteHost),
		fmt.Sprintf("net.exe use \\\\%s\\admin$ /delete", remoteHost),
		fmt.Sprintf("net.exe use \\\\%s\\c$ /delete", remoteHost),
		fmt.Sprintf("schtasks /s %s /delete /tn test_task /f", remoteHost),
	}

	for _, command := range commands {
		exec.Command("cmd.exe", "/C", command).Run()
	}

	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED: The test completed normally.
}