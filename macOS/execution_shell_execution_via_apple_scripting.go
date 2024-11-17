//go:build darwin
// +build darwin

/*
ID: d461fac0-43e8-49e2-85ea-3a58fe120b4f
NAME: Shell Execution via Apple Scripting
CREATED: 2024-06-28
scenario: execution of shell process [sh] via scripting [JXA/AppleScript]
*/
package main

import (
	_ "embed"
	"os"
	"os/exec"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

