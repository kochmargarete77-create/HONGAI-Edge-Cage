package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
)

const version = "0.1.0-tools-preview"

func execute(args []string) error {
	if len(args) == 0 || args[0] == "version" {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"name": "HONG AI Native Tool Privacy", "version": version, "componentOnly": true, "fullEnvironmentSimulation": false, "officialClientBundled": false, "physicalHardwareSimulation": false})
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	requestFile := flags.String("request", "", "Local installation request")
	root := flags.String("data-root", "", "Approved component data directory")
	bindingFile := flags.String("binding", "", "Protected upstream binding")
	file := flags.String("file", "", "Installer file selected by customer")
	source := flags.String("declared-source", "", "Operator-declared official HTTPS source")
	if e := flags.Parse(args[1:]); e != nil {
		return errors.New("INVALID_ARGUMENTS")
	}
	if flags.NArg() != 0 {
		return errors.New("UNEXPECTED_ARGUMENTS")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	switch args[0] {
	case "install":
		var r Request
		if e := decodeFile(*requestFile, &r); e != nil {
			return e
		}
		self, e := os.Executable()
		if e != nil {
			return errors.New("CURRENT_EXECUTABLE_UNAVAILABLE")
		}
		self, e = filepath.Abs(self)
		if e != nil {
			return e
		}
		result, e := install(r, self)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "restore":
		r, e := restore(*root)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(r)
	case "inspect-installer":
		r, e := inspectInstaller(*file, *source)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(r)
	case "bridge":
		binding, e := loadBinding(*bindingFile, *root)
		if e != nil {
			return e
		}
		stats, e := runBridge(ctx, binding, os.Stdin, os.Stdout)
		code := "SUCCESS"
		if e != nil {
			code = "BRIDGE_STOPPED"
		}
		writeAudit(*root, stats, code)
		return e
	default:
		return errors.New("COMMAND_NOT_SUPPORTED")
	}
}
func main() {
	if e := execute(os.Args[1:]); e != nil {
		code := e.Error()
		if !regexp.MustCompile(`^[A-Z0-9_]{1,100}$`).MatchString(code) {
			code = "OPERATION_FAILED_NO_RAW_DETAILS_EXPORTED"
		}
		fmt.Fprintln(os.Stderr, code)
		os.Exit(2)
	}
}
