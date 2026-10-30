package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/cps-kit/section7"

	"gopkg.in/yaml.v3"
)

func expandUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s expand -profile <profile.yaml>\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Print the profile with everything it inherits resolved.\n\n")
	fmt.Fprintf(os.Stderr, "  -profile file   Profile to expand (required)\n")
}

// runExpand implements the expand command.
func runExpand(args []string) {
	fs := flag.NewFlagSet("expand", flag.ExitOnError)
	profilePath := fs.String("profile", "", "profile to expand (required)")
	fs.Usage = expandUsage
	fs.Parse(args)

	if *profilePath == "" || fs.NArg() > 0 {
		expandUsage()
		os.Exit(1)
	}
	if err := expandProfile(*profilePath, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// expandProfile writes the profile at path with its `extends` chain resolved,
// which is the single document that the linter and the generator both see.
func expandProfile(path string, w io.Writer) error {
	loaded, err := section7.Load(path)
	if err != nil {
		return err
	}
	if validationErrs := loaded.Validate(); len(validationErrs) > 0 {
		for _, errMsg := range validationErrs {
			fmt.Fprintf(os.Stderr, "  - %s\n", errMsg)
		}
		return fmt.Errorf("profile %s has uninterpretable requirements", path)
	}

	var doc yaml.Node
	if err := doc.Encode(loaded.Raw); err != nil {
		return err
	}
	// The YAML encoder sorts map keys alphabetically; restore the order of a
	// profile and of the certificate it describes.
	orderKeys(&doc, []string{"profile", "requirements"})
	if req := mapValue(&doc, "requirements"); req != nil {
		orderKeys(req, section7.RequirementOrder)
		for _, name := range []string{"issuer", "subject"} {
			if attrs := mapValue(mapValue(req, name), "attributes"); attrs != nil {
				keys := make([]string, 0, len(attrs.Content)/2)
				for i := 0; i+1 < len(attrs.Content); i += 2 {
					keys = append(keys, attrs.Content[i].Value)
				}
				section7.SortAttributeKeys(keys)
				orderKeys(attrs, keys)
			}
		}
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	_, err = w.Write(out)
	return err
}

// mapValue returns the value stored under key in a mapping node, or nil.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// orderKeys reorders the entries of a mapping node to follow order. Keys not
// in order keep their relative positions after those that are.
func orderKeys(m *yaml.Node, order []string) {
	if m.Kind != yaml.MappingNode {
		return
	}
	rank := make(map[string]int, len(order))
	for i, key := range order {
		rank[key] = i
	}
	rankOf := func(key string) int {
		if r, ok := rank[key]; ok {
			return r
		}
		return len(order)
	}

	pairs := make([][2]*yaml.Node, 0, len(m.Content)/2)
	for i := 0; i+1 < len(m.Content); i += 2 {
		pairs = append(pairs, [2]*yaml.Node{m.Content[i], m.Content[i+1]})
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		return rankOf(pairs[i][0].Value) < rankOf(pairs[j][0].Value)
	})
	m.Content = m.Content[:0]
	for _, pair := range pairs {
		m.Content = append(m.Content, pair[0], pair[1])
	}
}
