// Command section7 generates CPS section 7 text from certificate profiles,
// lints certificates against them, and expands their inheritance.
//
// Negative serial numbers are parsed so that they are reported, not refused.
//
//go:debug x509negativeserial=1
package main

import (
	"fmt"
	"os"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <command> [flags]\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  generate   Generate a CPS document from a template and a directory of profiles\n")
	fmt.Fprintf(os.Stderr, "  lint       Lint a certificate against a profile\n")
	fmt.Fprintf(os.Stderr, "  expand     Print a profile with everything it inherits resolved\n\n")
	fmt.Fprintf(os.Stderr, "Run '%s <command> -h' for the flags of a command.\n", os.Args[0])
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch command, args := os.Args[1], os.Args[2:]; command {
	case "generate":
		runGenerate(args)
	case "lint":
		runLint(args)
	case "expand":
		runExpand(args)
	case "help", "-h", "-help", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command %q\n\n", command)
		usage()
		os.Exit(1)
	}
}
