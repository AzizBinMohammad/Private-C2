package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type ExportFormat string

const (
	FormatJSON ExportFormat = "json"
	FormatCEF  ExportFormat = "cef"
	FormatLEEF ExportFormat = "leef"
)

func Export(w io.Writer, entries []Entry, format ExportFormat) error {
	switch format {
	case FormatJSON:
		return exportJSON(w, entries)
	case FormatCEF:
		return exportCEF(w, entries)
	case FormatLEEF:
		return exportLEEF(w, entries)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}
}

func exportJSON(w io.Writer, entries []Entry) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

func exportCEF(w io.Writer, entries []Entry) error {
	for _, e := range entries {
		severity := mapSeverity(e.EventType)
		line := fmt.Sprintf("CEF:0|PrivateC2|TeamServer|1.0|%s|%s|%d|src=%s suser=%s msg=%s\n",
			e.EventType, e.Action, severity, e.SourceIP, e.OperatorID, escapeCEF(e.ResultSummary))
		if _, err := w.Write([]byte(line)); err != nil {
			return err
		}
	}
	return nil
}

func exportLEEF(w io.Writer, entries []Entry) error {
	for _, e := range entries {
		line := fmt.Sprintf("LEEF:2.0|PrivateC2|TeamServer|1.0|%s|src=%s\tusrName=%s\tmsg=%s\n",
			e.EventType, e.SourceIP, e.OperatorID, e.ResultSummary)
		if _, err := w.Write([]byte(line)); err != nil {
			return err
		}
	}
	return nil
}

func mapSeverity(eventType EventType) int {
	switch eventType {
	case EventKillSwitch, EventScopeViolation:
		return 10
	case EventSessionKill, EventPayloadRevoke:
		return 7
	case EventSessionInteract, EventPivot:
		return 5
	default:
		return 3
	}
}

func escapeCEF(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}
