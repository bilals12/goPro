//go:build linux
// +build linux

/*
ID: ff9bc8b9-f03b-4283-be58-ee0a16f5a11b
NAME: Potential Sudo Token Manipulation via Process Injection
CREATED: 2024-06-25
scenario: attach `gdb` to process with PID 1 [exists on all systems]
*/

package main

import (
    "os/exec"
    "syscall"
    "time"
    Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
    "linux": {"gdb", "--batch", "--eval-command='attach 1'", "--eval-command='detach'"}
}

func test() {
    command := supported[Endpoint.GetOS()]
    if Endpoint.IsAvailable(command[0]) {
        Endpoint.Say("[+] gdb available. attempting to attach to init process")

        cmd := exec.Command(command[0], command[1:]...)
        cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
        err := cmd.Run()
        if err != nil {
            Endpoint.Say("[-] gdb process execution blocked/failed")
            Endpoint.Stop(126)
        }

        // successful uid change event during sudo process execution
        Endpoint.Say("[+] simulating sudo execution with uid change")
        uidCmd := exec.Command("sudo", "whoami")
        uidCmd.SysProcAttr = &syscall.SysProcAttr{Setuid: true}
        err = uidCmd.Run()
        if err != nil {
            Endpoint.Say("[-] sudo execution with uid change blocked/failed")
            Endpoint.Stop(126)
        }

        // check for sudo token manipulation
        Endpoint.Say("[+] checking for token manipulation")
        if cmd.ProcessState.Success() && uidCmd.ProcessState.Success() {
            Endpoint.Say("[-] sudo token manipulation not blocked")
            Endpoint.Stop(101)
        }
    } else {
        Endpoint.Say("[-] gdb not available on this system")
        Endpoint.Stop(108)
    }
    Endpoint.Say("[+] test completed")
    Endpoint.Stop(100)
}

func main() {
    Endpoint.Start(test)
}