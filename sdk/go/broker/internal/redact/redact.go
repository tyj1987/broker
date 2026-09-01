// internal/redact: tiny redaction package to satisfy imports.
package redact

// Pattern is a placeholder type used by client.go to keep the import.
type Pattern struct {
	Name    string
	Pattern string
	Repl    string
}
