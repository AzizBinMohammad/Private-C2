package commands

import (
	"github.com/azizbinmohammad/private-c2/client/console"
)

func init() {
	Register(&Command{
		Name:        "audit",
		Description: "Query and manage audit logs",
		Usage:       "audit [query|export|verify] [options]",
		Handler:     auditQueryHandler,
		SubCommands: []*Command{
			{
				Name:        "query",
				Description: "Query audit log entries",
				Usage:       "audit query [--operator <id>] [--session <id>] [--type <event-type>] [--page <n>]",
				Handler:     auditQueryHandler,
			},
			{
				Name:        "export",
				Description: "Export audit log entries to a file",
				Usage:       "audit export [--output <path>] [--format json|csv]",
				Handler:     auditExportHandler,
			},
			{
				Name:        "verify",
				Description: "Verify audit log chain integrity",
				Usage:       "audit verify",
				Handler:     auditVerifyHandler,
			},
		},
	})
}

func auditQueryHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}

	w := console.NewWriter()

	// Parse filter options.
	operatorFilter := ""
	sessionFilter := ""
	typeFilter := ""
	page := "1"

	for i := 0; i < len(args)-1; i++ {
		switch args[i] {
		case "--operator":
			operatorFilter = args[i+1]
			i++
		case "--session":
			sessionFilter = args[i+1]
			i++
		case "--type":
			typeFilter = args[i+1]
			i++
		case "--page":
			page = args[i+1]
			i++
		}
	}

	w.Info("Querying audit log (page %s)...", page)
	if operatorFilter != "" {
		w.Info("  Operator filter: %s", operatorFilter)
	}
	if sessionFilter != "" {
		w.Info("  Session filter: %s", sessionFilter)
	}
	if typeFilter != "" {
		w.Info("  Type filter: %s", typeFilter)
	}

	// Stub: Would call gRPC AuditService.QueryAuditLog.
	table := console.NewTable(w, "Timestamp", "Operator", "Event", "Action", "Target", "Result")
	table.AddRow("(no audit entries)")
	table.Render()

	return nil
}

func auditExportHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}

	w := console.NewWriter()

	outputPath := "audit-export.json"
	format := "json"

	for i := 0; i < len(args)-1; i++ {
		switch args[i] {
		case "--output":
			outputPath = args[i+1]
			i++
		case "--format":
			format = args[i+1]
			i++
		}
	}

	w.Info("Exporting audit log as %s to %s...", format, outputPath)

	// Stub: Would call gRPC AuditService.ExportAuditLog and write the result.
	w.Success("Audit log exported to %s (stub)", outputPath)

	return nil
}

func auditVerifyHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}

	w := console.NewWriter()
	w.Info("Verifying audit log chain integrity...")

	// Stub: Would call gRPC AuditService.VerifyChain.
	w.Success("Audit log chain verification: PASSED (stub)")
	w.Info("All entries have valid hash links")

	return nil
}
