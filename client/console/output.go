package console

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// ANSI color codes for terminal output.
const (
	ColorReset   = "\033[0m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"
	ColorBold    = "\033[1m"
	ColorDim     = "\033[2m"
)

// OutputMode controls whether output is rendered as formatted text or JSON.
type OutputMode int

const (
	OutputText OutputMode = iota
	OutputJSON
)

// Writer handles formatted console output.
type Writer struct {
	out  io.Writer
	mode OutputMode
}

// NewWriter creates a new output writer. Defaults to stdout with text mode.
func NewWriter() *Writer {
	return &Writer{
		out:  os.Stdout,
		mode: OutputText,
	}
}

// SetOutput changes the underlying writer.
func (w *Writer) SetOutput(out io.Writer) {
	w.out = out
}

// SetMode changes the output mode (text or JSON).
func (w *Writer) SetMode(mode OutputMode) {
	w.mode = mode
}

// Info prints an informational message in cyan.
func (w *Writer) Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if w.mode == OutputJSON {
		w.writeJSON(map[string]string{"level": "info", "message": msg})
		return
	}
	fmt.Fprintf(w.out, "%s[*]%s %s\n", ColorCyan, ColorReset, msg)
}

// Success prints a success message in green.
func (w *Writer) Success(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if w.mode == OutputJSON {
		w.writeJSON(map[string]string{"level": "success", "message": msg})
		return
	}
	fmt.Fprintf(w.out, "%s[+]%s %s\n", ColorGreen, ColorReset, msg)
}

// Warn prints a warning message in yellow.
func (w *Writer) Warn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if w.mode == OutputJSON {
		w.writeJSON(map[string]string{"level": "warning", "message": msg})
		return
	}
	fmt.Fprintf(w.out, "%s[!]%s %s\n", ColorYellow, ColorReset, msg)
}

// Error prints an error message in red.
func (w *Writer) Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if w.mode == OutputJSON {
		w.writeJSON(map[string]string{"level": "error", "message": msg})
		return
	}
	fmt.Fprintf(w.out, "%s[-]%s %s\n", ColorRed, ColorReset, msg)
}

// Print writes unformatted output.
func (w *Writer) Print(format string, args ...interface{}) {
	fmt.Fprintf(w.out, format, args...)
}

// Println writes a line of unformatted output.
func (w *Writer) Println(args ...interface{}) {
	fmt.Fprintln(w.out, args...)
}

// Table renders a table with headers and rows using manual alignment.
type Table struct {
	Headers []string
	Rows    [][]string
	writer  *Writer
}

// NewTable creates a table with the given headers.
func NewTable(w *Writer, headers ...string) *Table {
	return &Table{
		Headers: headers,
		writer:  w,
	}
}

// AddRow adds a row of values to the table.
func (t *Table) AddRow(values ...string) {
	// Pad or truncate to match header count.
	row := make([]string, len(t.Headers))
	for i := range row {
		if i < len(values) {
			row[i] = values[i]
		}
	}
	t.Rows = append(t.Rows, row)
}

// Render prints the table to the writer.
func (t *Table) Render() {
	if t.writer.mode == OutputJSON {
		t.renderJSON()
		return
	}
	t.renderText()
}

// renderText renders the table as aligned text columns.
func (t *Table) renderText() {
	if len(t.Headers) == 0 {
		return
	}

	// Calculate column widths.
	widths := make([]int, len(t.Headers))
	for i, h := range t.Headers {
		widths[i] = len(h)
	}
	for _, row := range t.Rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Print header.
	headerLine := formatRow(t.Headers, widths)
	fmt.Fprintf(t.writer.out, "%s%s%s\n", ColorBold, headerLine, ColorReset)

	// Print separator.
	sep := make([]string, len(widths))
	for i, w := range widths {
		sep[i] = strings.Repeat("-", w)
	}
	fmt.Fprintln(t.writer.out, formatRow(sep, widths))

	// Print rows.
	for _, row := range t.Rows {
		fmt.Fprintln(t.writer.out, formatRow(row, widths))
	}

	fmt.Fprintf(t.writer.out, "\n%s%d rows%s\n", ColorDim, len(t.Rows), ColorReset)
}

// renderJSON renders the table as a JSON array of objects.
func (t *Table) renderJSON() {
	var records []map[string]string
	for _, row := range t.Rows {
		record := make(map[string]string)
		for i, h := range t.Headers {
			if i < len(row) {
				record[h] = row[i]
			}
		}
		records = append(records, record)
	}
	t.writer.writeJSON(records)
}

// formatRow formats a row of values with the given column widths.
func formatRow(values []string, widths []int) string {
	parts := make([]string, len(values))
	for i, v := range values {
		w := 10
		if i < len(widths) {
			w = widths[i]
		}
		parts[i] = padRight(v, w)
	}
	return strings.Join(parts, "  ")
}

// padRight pads a string to the given width with spaces.
func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

// writeJSON marshals data to JSON and writes it to the output.
func (w *Writer) writeJSON(data interface{}) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Fprintf(w.out, "{\"error\": %q}\n", err.Error())
		return
	}
	fmt.Fprintln(w.out, string(b))
}

// ColorizeStatus returns a status string colored according to its value.
func ColorizeStatus(status string) string {
	switch strings.ToLower(status) {
	case "healthy", "active", "connected", "running", "completed":
		return ColorGreen + status + ColorReset
	case "stale", "warning", "pending", "building":
		return ColorYellow + status + ColorReset
	case "lost", "dead", "failed", "revoked", "stopped":
		return ColorRed + status + ColorReset
	default:
		return status
	}
}

// ColorizeRole returns a role string with appropriate color.
func ColorizeRole(role string) string {
	switch role {
	case "admin":
		return ColorRed + role + ColorReset
	case "operator":
		return ColorGreen + role + ColorReset
	case "observer":
		return ColorBlue + role + ColorReset
	default:
		return role
	}
}
