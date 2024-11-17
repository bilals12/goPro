//go:build linux
// +build linux

/*
ID: b7c05aaf-78c2-4558-b069-87fa25973489
NAME: Potential Buffer Overflow Attack Detected
CREATED: 2023-12-11
scenario: try to write to a null pointer
*/

package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)


/*
try to write to null pointer, but generate segfault instead
*/
func generateSegfault() {
	code := `
	#include <stdio.h>
	int main() {
		int *p = NULL;
		*p = 42;
		return 0;
	}
	`

	// write code to temp file
	err := os.WriteFile("/tmp/segfault.c", []byte(code), 0644)
	if err != nil {
		fmt.Println("[-] failed to write segfauls code:", err)
		Endpoint.Stop(256) // unexpected error
		return
	}

	// compile code to binary
	cmd := exec.Command("gcc", "-o", "/tmp/segfault", "/tmp/segfault.c")
	err = cmd.Run()
	if err != nil {
		println("[-] failed to compile code:", err)
		Endpoint.Stop(256) // unexpected error
		return
	}

	// execute binary multiple times to generate multiple segfaults
	for i := 0; i < 100; i++ {
		cmd = exec.Command("/tmp/segfault")
		err = cmd.Run()
		if err != nil {
			fmt.Printf("[-] segfault %d execution failed: %v\n", i+1, err)
		}
		time.Sleep(100*time.Millisecond) // short delay to space out segfaults
	}
}

func test() {
	fmt.Println("[+] generating segfault events to simulate BOF attacks")
	generateSegfault()

	// check if events detected
	fmt.Println("[+] segfault events generated. checking for detection...")

	// success if no errors generated
	Endpoint.Stop(100) // protected
}

func main() {
	Endpoint.Start(test)
}