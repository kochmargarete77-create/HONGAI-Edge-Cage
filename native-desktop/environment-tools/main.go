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
	"strings"
	"time"
)

const version = "0.1.1-tools-preview"

var buildID = "development"

func execute(args []string) error {
	if len(args) > 0 && args[0] == "environment" {
		return executeEnvironment(args[1:])
	}
	if len(args) == 0 || args[0] == "version" {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"name": "HONG AI Native Environment Workbench and Tool Privacy", "version": version, "environmentVersion": environmentVersion, "buildID": buildID, "componentOnly": true, "fullEnvironmentSimulation": false, "officialClientBundled": false, "physicalHardwareSimulation": false})
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	requestFile := flags.String("request", "", "Local installation request")
	root := flags.String("data-root", "", "Approved component data directory")
	bindingFile := flags.String("binding", "", "Protected upstream binding")
	file := flags.String("file", "", "Installer file selected by customer")
	source := flags.String("declared-source", "", "Operator-declared official HTTPS source")
	directory := flags.String("directory", "", "Approved download directory")
	seconds := flags.Int("seconds", 120, "Bounded observation time")
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
	case "watch-downloads":
		if *seconds < 5 || *seconds > 900 {
			return errors.New("WATCH_DURATION_MUST_BE_5_TO_900_SECONDS")
		}
		watchContext, end := context.WithTimeout(ctx, time.Duration(*seconds)*time.Second)
		defer end()
		r, e := watchCandidates(watchContext, *directory, *source, 2*time.Second, 2*time.Second, inspectInstaller)
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
	args := os.Args[1:]
	desktopInvocation := len(args) == 0 && strings.HasPrefix(strings.ToLower(filepath.Base(os.Args[0])), "hongai-environment")
	if desktopInvocation {
		args = []string{"environment", "use"}
	}
	if e := execute(args); e != nil {
		code := e.Error()
		if !regexp.MustCompile(`^[A-Z0-9_]{1,100}$`).MatchString(code) {
			code = "OPERATION_FAILED_NO_RAW_DETAILS_EXPORTED"
		}
		fmt.Fprintln(os.Stderr, code)
		if desktopInvocation {
			presentEnvironmentFailure(code)
		}
		os.Exit(2)
	}
}
