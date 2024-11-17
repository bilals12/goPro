//go:build windows
// +build windows

/*
ID: e8dded92-4ef5-4322-8098-98e7cb33994f
NAME: Oversized Windows Script Execution
CREATED: 2024-06-29
scenario: large files to bypass online malware sandbox file upload size limits
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
	Endpoint.Say("[+] Starting Oversized Windows Script Execution VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	fileTypes := []string{"js", "jse", "vbs", "vbe", "wsh", "hta"}
	for _, fileType := range fileTypes {
		scriptPath := fmt.Sprintf("C:\\Temp\\script.%s", fileType)
		scriptContent := strings.Repeat("A", 30000001) // 30MB +1

		file, err := os.Create(scriptPath)
		if err != nil {
			Endpoint.Say(fmt.Sprintf("failed to create script file (%s): %v", fileType, err))
			Endpoint.Stop(1) // ERROR
		}
		defer file.Close()

		_, err = file.WriteString(scriptContent)
		if err != nil {
			Endpoint.Say(fmt.Sprintf("failed to write to script file (%s): %v", fileType, err))
			Endpoint.Stop(1) // ERROR
		}

		// execute script using `cscript.exe`, `wscript.exe`, `mshta.exe`
		executeCommand(fmt.Sprintf("cscript.exe %s", scriptPath))
		executeCommand(fmt.Sprintf("wscript.exe %s", scriptPath))
		executeCommand(fmt.Sprintf("mshta.exe %s", scriptPath))
	}
	Endpoint.Stop(101) // UNPROTECTED

	// execute command function
	func executeCommand(command string) {
		if !Endpoint.IsAvailable("cmd.exe") {
			Endpoint.Say("command execution not available")
			Endpoint.Stop(126) // PROTECTED
		}
		out, err := exec.Command("cmd.exe", "/C", command).CombinedOutput()
		if err != nil {
			Endpoint.Say(fmt.Sprintf("failed to execute command: %s", string(out)))
			Endpoint.Stop(1) // ERROR
		}
		Endpoint.Say(fmt.Sprintf("successfully executed command %s", command))

		if strings.Contains(string(out), "Access Denied") {
			Endpoint.Say("process execution blocked")
			Endpoint.Stop(126)
		}
	}
}

func cleanup {
	// remove files
	fileTypes := []string{"js", "jse", "vbs", "vbe", "wsh", "hta"}
	for _, fileType := range fileType {
		scriptPath := fmt.Sprintf("C:\\Temp\\script.%s", fileType)
		err := os.Remove(scriptPath)
		if err != nil {
			Endpoint.Say(fmt.Sprintf("failed to remove script file %s: %v", fileType, err))
		}
	}
	Endpoint.Say("cleanup completed!")
	Endpoint.Stop(100) // PROTECTED
}
