package main

import (
	"github.com/fatih/color"
	"github.com/akamensky/argparse"
	"os"
	"fmt"
	"strings"

	"github.com/000pp/sign/src/protocol"
)

func main() {
	color.Blue("sign - SMB and LDAP Signing Analyzer\n\n")

	parser := argparse.NewParser("sign", "Sign Argparser")
	target_address := parser.String("t", "target", &argparse.Options{Required: true, Help: "Specify target address or file with list of IPs"})
	protocol_flag := parser.String("p", "protocol", &argparse.Options{Required: true, Help: "Specify protocol to analyze"})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Println(parser.Usage(err))
		return
	}

	if strings.ToLower(*protocol_flag) != "smb" && strings.ToLower(*protocol_flag) != "ldap" {
		color.New(color.FgRed).Printf("[x] Invalid protocol '%s'. Use 'smb' or 'ldap'\n", *protocol_flag)
		return
	}

	targets, err := parseTargets(*target_address)
	if err != nil {
		color.New(color.FgRed).Printf("[x] Error parsing targets: %v\n", err)
		return
	}

	for _, target := range targets {
		
		if strings.ToLower(*protocol_flag) == "smb" {
			protocol.StartSMB(target)
		}

		if strings.ToLower(*protocol_flag) == "ldap" {
			protocol.StartLDAP(target)
		}
	}
}

func parseTargets(target string) ([]string, error) {
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		data, err := os.ReadFile(target)
		if err != nil {
			return nil, fmt.Errorf("unable to open the file %s: %v", target, err)
		}

		lines := strings.Split(string(data), "\n")
		var targets []string
		for _, line := range lines {
			if t := strings.TrimSpace(line); t != "" {
				targets = append(targets, t)
			}
		}

		if len(targets) == 0 {
			return nil, fmt.Errorf("no valid target found in the file")
		}
		return targets, nil
	}

	return []string{target}, nil
}