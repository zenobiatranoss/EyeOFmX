// EyeOFmX — native Linux desktop monitoring and security inspection.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"eyeofmx/internal/gui"
	"eyeofmx/internal/scan"
	"eyeofmx/internal/setup"
	"eyeofmx/internal/sysutil"
)

const version = "1.0.1"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	checkOnly := flag.Bool("check", false, "run a non-GUI privilege/tool check and exit")
	scanOnly := flag.Bool("scan", false, "run a quick non-GUI posture scan and exit")
	scanFull := flag.Bool("scan-full", false, "run the full non-GUI comprehensive scan and exit")
	fullGUIScan := flag.Bool("full-scan", false, "start the GUI and run the full comprehensive scan immediately")
	setupPlan := flag.Bool("setup-plan", false, "print the automatic tool-installation plan and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("EyeOFmX " + version)
		return
	}
	if *checkOnly {
		printDiagnostics()
		return
	}
	if *setupPlan {
		printSetupPlan()
		return
	}
	if *scanOnly || *scanFull {
		options := scan.Quick()
		if *scanFull {
			options = scan.Full()
		}
		fmt.Println(scan.FormatBrief(scan.Scan(options)))
		return
	}
	if *fullGUIScan {
		if err := gui.RunWithFullScan(); err != nil {
			fmt.Fprintln(os.Stderr, "EyeOFmX: startup failed:", err)
			os.Exit(1)
		}
		return
	}

	if !sysutil.IsRoot() {
		// Deliberately non-fatal: most collectors degrade gracefully.
		fmt.Fprintln(os.Stderr,
			"EyeOFmX: running unprivileged — some /proc, /etc and log data will be unavailable.")
	}
	if err := gui.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "EyeOFmX: startup failed:", err)
		os.Exit(1)
	}
}

func printSetupPlan() {
	plan := setup.BuildPlan()
	fmt.Printf("EyeOFmX %s tool setup plan\n", version)
	fmt.Printf("distribution : %s (%s)\n", plan.Distro.Preview, plan.Distro.Family)
	fmt.Printf("missing      : %s\n", strings.Join(orNone(plan.Missing), ", "))
	fmt.Printf("auto         : %s\n", strings.Join(orNone(plan.AutoMissing), ", "))
	fmt.Printf("manual       : %s\n", strings.Join(orNone(plan.ManualMissing), ", "))
	packages := make([]string, 0, len(plan.Packages))
	for _, p := range plan.Packages {
		packages = append(packages, p.Name)
	}
	fmt.Printf("packages     : %s\n", strings.Join(orNone(packages), ", "))
	if plan.Command == "" {
		fmt.Println("install command : not available for this distribution")
	} else {
		fmt.Println("install command :")
		fmt.Print(plan.Command)
	}
	if len(plan.Notes) > 0 {
		fmt.Println("notes :")
		for _, note := range plan.Notes {
			fmt.Println("  - " + note)
		}
	}
}

func orNone(values []string) []string {
	if len(values) == 0 {
		return []string{"none"}
	}
	return values
}

func printDiagnostics() {
	priv := "unprivileged"
	if sysutil.IsRoot() {
		priv = "root"
	}
	init := "sysinit/OpenRC/runit"
	if sysutil.IsSystemd() {
		init = "systemd"
	}
	fmt.Printf("EyeOFmX %s diagnostics\nprivileges: %s\ninit: %s\nlibc: %s\nkernel: %s\n",
		version, priv, init, sysutil.Libc(), sysutil.KernelRelease())
	for _, tool := range sysutil.ToolList() {
		state := "missing"
		binary := "-"
		if tool.Available {
			state = "available"
			binary = tool.Binary
		}
		fmt.Printf("  %-14s %-10s %s\n", tool.Capability+":", state, binary)
	}
}
