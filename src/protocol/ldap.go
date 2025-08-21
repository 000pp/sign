package protocol

import (
	"crypto/tls"
	"fmt"
	"log"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type LDAPStatus struct {
	Protocol string
	Signing  string
}

func StartLDAP(target_address string) LDAPStatus {
	status := checkLDAP(target_address)
	
	if status.Protocol != "" {
		fmt.Printf("%s:389 - %s\n", target_address, status.Signing)
		return status
	}

	statusTLS := checkLDAPS(target_address)
	if statusTLS.Protocol != "" {
		fmt.Printf("%s:636 - %s\n", target_address, statusTLS.Signing)
	}
	
	return statusTLS
}

func checkLDAP(target_address string) LDAPStatus {
	address := fmt.Sprintf("ldap://%s:389", target_address)
	conn, err := ldap.DialURL(address)
	if err != nil {
		log.Printf("LDAP connection failed: %v", err)
		return LDAPStatus{}
	}
	defer conn.Close()

	err = conn.UnauthenticatedBind("")
	if err != nil {
		if signingErrorHandler(err) {
			return LDAPStatus{Protocol: "LDAP", Signing: "Enabled and required"}
		}
		return LDAPStatus{Protocol: "LDAP", Signing: "Disabled"}
	}

	if supportsSigningOptional(target_address) {
		return LDAPStatus{Protocol: "LDAP", Signing: "Enabled, but not required"}
	}
	
	return LDAPStatus{Protocol: "LDAP", Signing: "Disabled"}
}

func supportsSigningOptional(target_address string) bool {
	address := fmt.Sprintf("ldap://%s:389", target_address)
	conn, err := ldap.DialURL(address)
	if err != nil {
		return false
	}
	defer conn.Close()

	err = conn.StartTLS(&tls.Config{InsecureSkipVerify: true})
	
	if err != nil {return false}

	return true
}

func checkLDAPS(target_address string) LDAPStatus {
	address := fmt.Sprintf("ldaps://%s:636", target_address)
	conn, err := ldap.DialURL(address, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))

	if err != nil {return LDAPStatus{}
}
	defer conn.Close()

	return LDAPStatus{Protocol: "LDAPS", Signing: "Enabled and required"}
}

func signingErrorHandler(err error) bool {
	errorMessage := strings.ToLower(err.Error())
	keywords := []string{
		"signing required",
		"authentication required", 
		"bind required",
		"security required",
		"confidentiality required",
	}
	
	for _, keyword := range keywords {if strings.Contains(errorMessage, keyword) {return true}}
	return false
}