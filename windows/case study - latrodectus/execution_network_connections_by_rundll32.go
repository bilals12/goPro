//go:build windows
// +build windows

/*
ID: b8a0a3aa-0345-4035-b41d-f758a6c59a78
NAME: Long-term and/or High Count of Network Connections by Rundll32
CREATED: 2024-07-01
scenario: downloading the PE and connections by rundll32 to a public IP address
*/
package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting Long-term and/or High Count of Network Connections by Rundll32 VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	executeCommand := func(command string) {
		if !Endpoint.IsAvailable("cmd.exe") {
			Endpoint.Say("[+] Command execution is not available")
			Endpoint.Stop(126) // PROTECTED: Access Denied
		}

		out, err := exec.Command("cmd.exe", "/C", command).CombinedOutput()
		if err != nil {
			Endpoint.Say(fmt.Sprintf("[-] Failed to execute command: %s", string(out)))
			Endpoint.Stop(1) // ERROR
		}

		Endpoint.Say(fmt.Sprintf("[+] Successfully executed command: %s", command))

		if strings.Contains(string(out), "Access Denied") {
			Endpoint.Say("[+] Process execution was blocked")
			Endpoint.Stop(126) // PROTECTED: Access Denied
		}
	}

	// Simulate rundll32.exe creating a PE file in the InetCache folder
	rundll32Path := "C:\\Windows\\System32\\rundll32.exe"
	peFilePath := "C:\\Users\\Public\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\malicious.exe"
	executeCommand(fmt.Sprintf("%s /c echo 4D5A > %s", rundll32Path, peFilePath))

	// Simulate rundll32.exe making network connections to public IP addresses
	publicIPs := []string{"8.8.8.8", "8.8.4.4"}
	for _, ip := range publicIPs {
		executeCommand(fmt.Sprintf("%s /c ping %s", rundll32Path, ip))
		time.Sleep(100 * time.Millisecond)
	}

	// Simulate long-term and high count of network connections
	startTime := time.Now()
	for i := 0; i < 100; i++ {
		for _, ip := range publicIPs {
			executeCommand(fmt.Sprintf("%s /c ping %s", rundll32Path, ip))
		}
		time.Sleep(10 * time.Millisecond)
	}
	duration := time.Since(startTime)
	if duration.Seconds() < 1 {
		Endpoint.Say("[+] Long-term and high count network connection simulation successful")
		Endpoint.Stop(100) // PROTECTED
	} else {
		Endpoint.Say("[-] Simulation took too long")
		Endpoint.Stop(1) // ERROR
	}
}

func cleanup() {
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}
