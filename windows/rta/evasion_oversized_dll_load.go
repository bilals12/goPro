//go:build windows
// +build windows

/*
ID: ec52377c-b2a8-4c44-8eb4-465376f2189a
NAME: Oversized DLL Creation followed by SideLoad
CREATED: 2024-06-29
scenarios: oversized DLL creation followed by sideload; potential evasion via oversized image load
rundll32 or regsvr executing oversized file
DLL side loading via copied MS .EXE
rundll32/regsvr32 loads dropped exe
*/
package main

import (
	"fmt"
	"os"
	"os/exec"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting Oversized DLL Creation followed by SideLoad VST")
	Endpoint.Start(test, cleanup)
}


/*
define paths of DLL + exe
check if DLL exits
copy required DLL + exe to temp locations
append null bytes to the DLL to make it oversized [90MB]
execute commands to trigger DLL sideloading
*/
func test() {
	// this DLL will spawn once DllMain is invoked
	dll := "faultrep.dll"
	// this .exe will sideload faultrep.dll
	wer := "C:\\Windows\\System32\\werfault.exe"
	tempDir := os.Getenv("localappdata") + "\\Temp\\"
	tempc := tempDir + "oversized.dll"
	rtaDll := tempDir + "faultrep.dll"
	rtaPe := tempDir + "wer.exe"

	if !Endpoint.Exists(dll) {
		Endpoint.Say(fmt.Sprintf("file doesn't exist", dll))
		Endpoint.Stop(104) // NOT RELEVANT
	}

	Endpoint.Say(fmt.Sprintf("copying %s to %s", dll, tempc))
	err := Endpoint.CopyFile(dll, tempc)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("failed to copy %s to %s", dll, tempc))
		Endpoint.Stop(1) // ERROR
	}

	Endpoint.Say(fmt.Sprintf("copying %s to %s", wer, rtaPe))
	err = Endpoint.CopyFile(wer, rtaPe)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("failed to copy %s to %s", wer, rtaPe))
		Endpoint.Stop(1) // ERROR
	}

	// append null bytes to the file tempc to increase its size
	Endpoint.Say(fmt.Sprintf("file %s will be appended with null bytes", tempc))
	file, err := os.OpenFile(tempc, os.O_RDWR, 0644)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("failed to open file", tempc))
		Endpoint.Stop(1) // ERROR
	}
	defer file.Close()

	_, err = file.Seek(100000000, 0)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("failed to seek file %s", tempc))
		Endpoint.Stop(1) // ERROR
	}

	_, err = file.Write([]byte{0x00})
	if err != nil {
		Endpoint.Say(fmt.Sprintf("failed to write to file %s", tempc))
		Endpoint.Stop(1)
	}

	/*
	copy oversized DLL to another location via `cmd.exe`
	execute `rundll32` with oversized DLL + `werfault.exe` to trigger sideloading
	*/
	Endpoint.Say(fmt.Sprintf("copying %s to %s via cmd.exe", tempc, rtaDll))
	cmd := exec.Command("cmd.exe", "/c", "copy", tempc, rtaDll)
	out, err := cmd.CombinedOutput()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("failed to copy %s to %s via cmd.exe", tempc, rtaDll))
		Endpoint.Stop(1) // ERROR
	}

	if Endpoint.Exists(rtaDll) && Endpoint.Exists(rtaPe) {
		Endpoint.Say("executing rundll32 with oversized DLL")
		cmd = exec.Command("rundll32.exe", rtaDll, "DllMain")
		out, err = cmd.CombinedOutput()
		if err != nil {
			Endpoint.Say(fmt.Sprintf("failed to execute rundll32: %s", string(out)))
			Endpoint.Stop(1)
		}
		Endpoint.Say("executing werfault.exe to trigger DLL side-loading")
		cmd = exec.Command(rtaPe)
		out, err = cmd.CombinedOutput()
		if err != nil {
			Endpoint.Say(fmt.Sprintf("failed to execute werfault.exe: %s", string(out)))
			Endpoint.Stop(1) // ERROR
		}
	} else {
		Endpoint.Say(fmt.Sprintf("files %s or %s don't exist", rtaDll, rtaPe))
		Endpoint.Stop(1) // ERROR
	}

	Endpoint.Say("successfully executed commands")
	Endpoint.Stop(101) // UNPROTECTED
}

func cleanup() {
	tempc := os.Getenv("localappdata") + "\\Temp\\oversized.dll"
	rtaDll := os.Getenv("localappdata") + "\\Temp\\faultrep.dll"
	rtaPe := os.Getenv("localappdata") + "\\Temp\\wer.exe"

	err := exec.Command("taskkill", "/f", "/im", "notepad.exe").Run()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("failed to kill notepad.exe: %s", err))
	}

	files := []string(tempc, rtaDll, rtaPe)
	for _, file := range files {
		if Endpoint.Exists(file) {
			err := os.Remove(file)
			if err != nil {
				Endpoint.Say(fmt.Sprintf("failed to remove file %s: %s", file, err))
			} else {
				Endpoint.Say(fmt.Sprintf("removed file %s", file))
			}
		}
	}
	Endpoint.Say("cleanup completed successfully!")
	Endpoint.Stop(100) // PROTECTED
}