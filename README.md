# sign

A small project to detect if signing is enabled and required for SMB and LDAP (not implemeted yet)

### Usage:

```
sign -t <ip/file> -p <protocol>
```

### Example:

```
$ go run main.go -t ips.txt -p smb

sign - SMB and LDAP Signing Analyzer

192.168.15.52:445 - Enabled, but not required
192.168.15.53:445 - Enabled, but not required
```