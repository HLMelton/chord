package main

#Firewall util for adding ports 1433 and 1434

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

func isAdmin() bool{
	var sid *windows.SID
	sid, _ = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	token := windows.Token(0)

	isMember, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return isMember
}

func runAsAdmin() error {
	exe,err:= os.Executable()
	if err!= nil {
		return err
	}
	exe, _ = filepath.EvalSymlinks(exe)

	verb := "runas"

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Verb: verb,
	}
	return cmd.Start()
}

func main() {
	if !isAdmin() {
		fmt.Println("Not running as admin. Requesting elevation...")
		err:= runAsAdmin()
		if err != nil {
			fmt.Println("Failed to elevate permissions", err)
		}
		return
	}

	fmt.Println("Running with Admin...")
	ruleName := "SQLServer default instance"
	port := "1433"
	protocol := "TCP"

	cmd := exec.Command(
	"netsh", "advfirewall", "firewall","add","rule", 
	fmt.Sprintf("name=%s", ruleName),
	"dir=in",
	"action=allow",
	fmt.Sprintf("protocol=%s",protocol),
	fmt.Sprintf("localport=%s",port),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error creating firewall rule", err)
	}
	fmt.Println(string(output))
}
