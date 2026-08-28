package main

// restartArgs preserves runtime configuration while suppressing browser UI
// side effects. The already-open dashboard reconnects to the same process/port
// after exec; retaining --open-ui would incorrectly create a second tab.
func restartArgs(args []string) []string {
	clean := make([]string, 0, len(args)+1)
	backgroundPresent := false
	for _, arg := range args {
		switch arg {
		case "--open-ui", "-open-ui":
			continue
		case "--background", "-background", "--autostart", "-autostart":
			backgroundPresent = true
		}
		clean = append(clean, arg)
	}
	if !backgroundPresent {
		clean = append(clean, "--background")
	}
	return clean
}
