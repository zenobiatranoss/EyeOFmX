package gui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/gotk3/gotk3/gtk"

	"eyeofmx/internal/setup"
	"eyeofmx/internal/sysutil"
)

// elevationMethod returns the least surprising way to obtain root privileges
// on the current desktop. pkexec uses the system polkit agent (a native GUI
// prompt); sudo/doas use our own native GTK password dialog.
func elevationMethod() string {
	if sysutil.IsRoot() {
		return "root"
	}
	if sysutil.Available("pkexec") {
		return "pkexec"
	}
	if sysutil.Available("sudo") {
		return "sudo"
	}
	if sysutil.Available("doas") {
		return "doas"
	}
	return ""
}

// askPassword shows a small native GTK dialog. The password is used only for
// the single command that follows and is never written to disk or logged.
func askPassword(parent gtk.IWindow, title, label string) (string, bool) {
	d, err := gtk.DialogNew()
	if err != nil {
		return "", false
	}
	d.SetTransientFor(parent)
	d.SetModal(true)
	d.SetTitle(title)
	area, err := d.GetContentArea()
	if err != nil {
		d.Destroy()
		return "", false
	}
	box := mustBox(gtk.ORIENTATION_VERTICAL, 8)
	box.SetBorderWidth(14)
	box.PackStart(mustLabel(label), false, false, 0)
	entry, err := gtk.EntryNew()
	if err != nil {
		d.Destroy()
		return "", false
	}
	entry.SetVisibility(false)
	box.PackStart(entry, false, false, 0)
	area.PackStart(box, false, false, 0)
	if _, err := d.AddButton("Cancel", gtk.RESPONSE_CANCEL); err != nil {
		d.Destroy()
		return "", false
	}
	if _, err := d.AddButton("Continue", gtk.RESPONSE_ACCEPT); err != nil {
		d.Destroy()
		return "", false
	}
	d.ShowAll()
	response := d.Run()
	text, _ := entry.GetText()
	d.Destroy()
	if response != gtk.RESPONSE_ACCEPT || text == "" {
		return "", false
	}
	return text, true
}

// installScanTools is the action behind the menu item and the scan-tab button.
func (a *App) installScanTools() {
	a.installScanToolsWithPlan(setup.BuildPlan())
}

func (a *App) installScanToolsWithPlan(plan setup.Plan) {
	if plan.Command == "" {
		var b strings.Builder
		b.WriteString("No automatic package mapping is available for this distribution.\n\n")
		for _, note := range plan.Notes {
			b.WriteString(note + "\n")
		}
		showInfo(a.window, "Install scanning tools", b.String())
		return
	}

	method := elevationMethod()
	if method == "" {
		showError(a.window, "Install scanning tools",
			"No authentication tool was found. Install pkexec, sudo or doas, or run EyeOFmX as root and try again.")
		return
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Distribution : %s (%s)\n", plan.Distro.Preview, plan.Distro.Family)
	fmt.Fprintf(&b, "Missing      : %s\n", strings.Join(plan.Missing, ", "))
	if len(plan.ManualMissing) > 0 {
		fmt.Fprintf(&b, "Manual-only  : %s (see notes)\n", strings.Join(plan.ManualMissing, ", "))
	}
	b.WriteString("Packages     : ")
	names := make([]string, 0, len(plan.Packages))
	for _, p := range plan.Packages {
		names = append(names, p.Name)
	}
	b.WriteString(strings.Join(names, " "))
	b.WriteString("\n\nCommand to run:\n")
	b.WriteString(plan.Command)
	if len(plan.Notes) > 0 {
		b.WriteString("\nNotes:\n")
		for _, note := range plan.Notes {
			b.WriteString("  - " + note + "\n")
		}
	}
	b.WriteString("\nThis will install packages on your system. Continue?\n")
	if method == "pkexec" {
		b.WriteString("Authentication: the system polkit dialog will ask for your password.")
	} else if method == "root" {
		b.WriteString("Authentication: EyeOFmX is already running as root.")
	} else {
		b.WriteString("Authentication: EyeOFmX will ask for your " + method + " password.")
	}

	d := gtk.MessageDialogNew(a.window, gtk.DIALOG_MODAL, gtk.MESSAGE_QUESTION,
		gtk.BUTTONS_YES_NO, "%s", b.String())
	d.SetTitle("Install scanning tools")
	response := d.Run()
	d.Destroy()
	if response != gtk.RESPONSE_YES {
		return
	}

	password := ""
	if method == "sudo" || method == "doas" {
		var ok bool
		password, ok = askPassword(a.window, method+" authentication",
			"Enter your "+method+" password to install the scanning tools:")
		if !ok {
			return
		}
	}
	a.runInstaller(plan, method, password)
}

// runInstaller shows live package-manager output and offers to restart the GUI
// as root so the newly installed engines can run immediately.
func (a *App) runInstaller(plan setup.Plan, method, password string) {
	d, err := gtk.DialogNew()
	if err != nil {
		return
	}
	d.SetTransientFor(a.window)
	d.SetTitle("Installing scanning tools")
	d.SetModal(true)
	d.SetDefaultSize(820, 520)
	area, err := d.GetContentArea()
	if err != nil {
		d.Destroy()
		return
	}
	root := mustBox(gtk.ORIENTATION_VERTICAL, 6)
	root.SetBorderWidth(10)
	status := mustLabel("Waiting for authentication…")
	root.PackStart(status, false, false, 0)
	terminal := newTerminal("eye-terminal")
	root.PackStart(newScrolled(terminal), true, true, 0)
	area.PackStart(root, true, true, 0)

	closeBtn, err1 := d.AddButton("Close", gtk.RESPONSE_CLOSE)
	restartBtn, err2 := d.AddButton("Restart as root and run full scan", gtk.RESPONSE_ACCEPT)
	if err1 != nil || err2 != nil {
		d.Destroy()
		return
	}
	closeBtn.SetSensitive(false)
	restartBtn.SetSensitive(false)
	// A running package transaction must not be interrupted by an accidental
	// window close; the window is closable again when the command finishes.
	finished := false
	d.Connect("delete-event", func() bool { return !finished })
	d.ShowAll()

	go func() {
		var output strings.Builder
		onLine := func(line string) {
			output.WriteString(line)
			output.WriteString("\n")
			idle(func() { appendText(terminal, line+"\n", "", true) })
		}
		installErr := runElevated(method, password, plan.Command, onLine)
		installed, failed := setup.ParseResult(output.String(), plan.Packages)
		idle(func() {
			finished = true
			closeBtn.SetSensitive(true)
			restartBtn.SetSensitive(installErr == nil && len(installed) > 0)
			if installErr != nil {
				status.SetText("Installer returned an error: " + installErr.Error())
			} else {
				status.SetText(fmt.Sprintf("Done — %d package(s) confirmed, %d failed. Restart as root to run the full scan.",
					len(installed), len(failed)))
			}
			appendText(terminal, "\n[setup] installed: "+strings.Join(installed, ", ")+"\n", "term-ok", true)
			if len(failed) > 0 {
				appendText(terminal, "[setup] failed: "+strings.Join(failed, ", ")+"\n", "risk-medium", true)
			}
		})
	}()

	response := d.Run()
	d.Destroy()
	if response == gtk.RESPONSE_ACCEPT && finished {
		a.relaunchAsRoot(method, password)
	}
}

// runElevated executes one shell command with the chosen authentication
// method and streams both stdout and stderr line by line.
func runElevated(method, password, command string, onLine func(string)) error {
	var cmd *exec.Cmd
	switch method {
	case "root":
		cmd = exec.Command("sh", "-c", command)
	case "pkexec":
		cmd = exec.Command("pkexec", "sh", "-c", command)
	case "sudo":
		cmd = exec.Command("sudo", "-S", "-p", "", "sh", "-c", command)
		cmd.Stdin = strings.NewReader(password + "\n")
	case "doas":
		cmd = exec.Command("doas", "-S", "sh", "-c", command)
		cmd.Stdin = strings.NewReader(password + "\n")
	default:
		return fmt.Errorf("no supported elevation method")
	}
	cmd.Env = append(os.Environ(), "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	var wg sync.WaitGroup
	for _, reader := range []io.Reader{stdout, stderr} {
		wg.Add(1)
		go func(r io.Reader) {
			defer wg.Done()
			scanner := bufio.NewScanner(r)
			scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for scanner.Scan() {
				onLine(scanner.Text())
			}
		}(reader)
	}
	waitErr := cmd.Wait()
	wg.Wait()
	return waitErr
}

// relaunchAsRoot starts a new EyeOFmX process as root with the original
// display environment and the -full-scan flag, then quits the current one.
func (a *App) relaunchAsRoot(method, password string) {
	exe, err := os.Executable()
	if err != nil {
		showError(a.window, "Restart as root", "Could not determine the executable path: "+err.Error())
		return
	}
	envParts := []string{}
	for _, key := range []string{"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		if value := os.Getenv(key); value != "" {
			envParts = append(envParts, key+"="+setup.ShellQuote(value))
		}
	}
	inner := "env " + strings.Join(envParts, " ") + " " + setup.ShellQuote(exe) + " -full-scan"
	var cmd *exec.Cmd
	switch method {
	case "root":
		cmd = exec.Command("sh", "-c", inner)
	case "pkexec":
		cmd = exec.Command("pkexec", "sh", "-c", inner)
	case "sudo":
		cmd = exec.Command("sudo", "-S", "-p", "", "sh", "-c", inner)
		cmd.Stdin = strings.NewReader(password + "\n")
	case "doas":
		cmd = exec.Command("doas", "-S", "sh", "-c", inner)
		cmd.Stdin = strings.NewReader(password + "\n")
	default:
		return
	}
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		showError(a.window, "Restart as root", "Could not restart EyeOFmX as root: "+err.Error())
		return
	}
	gtk.MainQuit()
}

// offerScanToolInstall asks once at startup when important scanning engines
// are missing. It never installs anything without an explicit Yes.
func (a *App) offerScanToolInstall() {
	plan := setup.BuildPlan()
	if len(plan.AutoMissing) == 0 || plan.Command == "" {
		return
	}
	msg := fmt.Sprintf("Missing scanning engines: %s\n\n"+
		"EyeOFmX can install the matching packages for %s automatically. "+
		"It will request root privileges through your system's authentication dialog.\n\n"+
		"Install them now?", strings.Join(plan.AutoMissing, ", "), plan.Distro.Preview)
	d := gtk.MessageDialogNew(a.window, gtk.DIALOG_MODAL, gtk.MESSAGE_QUESTION,
		gtk.BUTTONS_YES_NO, "%s", msg)
	d.SetTitle("Install scanning tools")
	response := d.Run()
	d.Destroy()
	if response == gtk.RESPONSE_YES {
		a.installScanToolsWithPlan(plan)
	}
}
