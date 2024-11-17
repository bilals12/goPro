//go:build windows
// +build windows

/*
ID: b0a0d293-f85e-4994-97e6-95541c0bc181
NAME: Execution via a Suspicious WMI Client
CREATED: 2024-06-30
scenario: Identifies the execution of a process via Windows Management Instrumentation (WMI) and with an unusual effective parent.
Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads.
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
	Endpoint.Say("[+] Starting Execution via a Suspicious WMI Client VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	effectiveParents := []string{"excel.exe", "powerpnt.exe", "winword.exe", "mshta.exe", "wscript.exe", "wmic.exe", "rundll32.exe", "regsvr.exe", "msbuild.exe", "InstallUtil.exe"}
	parentPaths := []string{"C:\\Users\\Public\\*", "C:\\ProgramData\\*", "C:\\Users\\*\\AppData\\*", "C:\\Windows\\Microsoft.NET\\*"}
	hashExclusions := []string{
		"0e692d9d3342fdcab1ce3d61aed0520989a94371e5898edb266c92f1fe11c97f",
		"8ee339af3ce1287066881147557dc3b57d1835cbba56b2457663068ed25b7840",
		"f27cb78f44fc8f70606be883bbed705bd1dd2c2f8a84a596e5f4924e19068f22",
	}
	executableExclusions := []string{
		"C:\\Windows\\System32\\WerFault.exe",
		"C:\\Windows\\SysWOW64\\WerFault.exe",
		"C:\\Windows\\System32\\typeperf.exe",
		"C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\AcroTray.exe",
		"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
		"C:\\Program Files\\Mozilla Firefox\\firefox.exe",
	}

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

	// process starting via WMI with unusual parent
	for _, parent := range effectiveParents {
		executeCommand(fmt.Sprintf("powershell.exe Start-Process -FilePath 'C:\\Windows\\System32\\Wbem\\WmiPrvSE.exe' -ArgumentList 'wmic process call create C:\\Windows\\System32\\cmd.exe' -Wait"))
		executeCommand(fmt.Springf("powershell.exe Start-Process -FilePath 'C:\\Windows\\System32\\cmd.exe' -ArgumentList '/C whoami'"))
	}

	for _, path := range parentPaths {
		executeCommand(fmt.Sprintf("powershell.exe Start-Process -FilePath 'C:\\Windows\\System32\\Wbem\\WmiPrvSE.exe' -ArgumentList 'wmic process call create %s\\cmd.exe' -Wait", path))
		executeCommand(fmt.Sprintf("powershell.exe Start-Process -FilePath '%s\\cmd.exe' -ArgumentList '/C whoami'", path))
	}

	Endpoint.Stop(101) // UNPROTECTED
}

func cleanup() {
	// No specific cleanup actions required for this VST
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}