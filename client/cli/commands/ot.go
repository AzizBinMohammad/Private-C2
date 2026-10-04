package commands

import (
	"fmt"

	"github.com/azizbinmohammad/private-c2/client/console"
)

// OT commands are hidden from the default command listing.
// They appear only when the operator has the ot.assess permission.

func init() {
	Register(&Command{
		Name:        "ot",
		Description: "OT/ICS Assessment (hidden - requires ot.assess)",
		Usage:       "ot [discover|scan|capture|topology|compliance|report|creds|hmi|wireless|serial|estop] [args]",
		Handler:     otHelpHandler,
		SubCommands: []*Command{
			{
				Name:        "discover",
				Description: "Discover OT/ICS assets on the network",
				Usage:       "ot discover [--passive] [--active] [--timeout <seconds>]",
				Handler:     otDiscoverHandler,
			},
			{
				Name:        "scan",
				Description: "Scan an OT asset for vulnerabilities (offline CVE correlation)",
				Usage:       "ot scan <target-ip> [--protocol <proto>]",
				Handler:     otScanHandler,
			},
			{
				Name:        "capture",
				Description: "Capture OT protocol traffic (passive)",
				Usage:       "ot capture [--duration <seconds>] [--protocols <list>]",
				Handler:     otCaptureHandler,
			},
			{
				Name:        "topology",
				Description: "Build OT network topology (Purdue model)",
				Usage:       "ot topology [--format json|dot]",
				Handler:     otTopologyHandler,
			},
			{
				Name:        "compliance",
				Description: "Run compliance gap analysis",
				Usage:       "ot compliance [--framework iec62443|nist80082|nerccip]",
				Handler:     otComplianceHandler,
			},
			{
				Name:        "report",
				Description: "Generate OT assessment report",
				Usage:       "ot report [--format json|markdown|csv|mitre]",
				Handler:     otReportHandler,
			},
			{
				Name:        "creds",
				Description: "Test for default credentials (single attempt per cred)",
				Usage:       "ot creds <target-ip> [--vendor <vendor>]",
				Handler:     otCredsHandler,
			},
			{
				Name:        "hmi",
				Description: "Assess HMI web interfaces (HTTP GET only)",
				Usage:       "ot hmi <target-ip>",
				Handler:     otHMIHandler,
			},
			{
				Name:        "wireless",
				Description: "Detect wireless in OT environment",
				Usage:       "ot wireless",
				Handler:     otWirelessHandler,
			},
			{
				Name:        "serial",
				Description: "Enumerate serial ports and fieldbus gateways",
				Usage:       "ot serial",
				Handler:     otSerialHandler,
			},
			{
				Name:        "plc",
				Description: "Read PLC program metadata (read-only)",
				Usage:       "ot plc <target-ip> [--protocol s7|modbus|ethernetip]",
				Handler:     otPLCHandler,
			},
			{
				Name:        "assets",
				Description: "List discovered OT assets",
				Usage:       "ot assets [--purdue-level <0-5>] [--vendor <vendor>]",
				Handler:     otAssetsHandler,
			},
			{
				Name:        "segmentation",
				Description: "Analyze network segmentation",
				Usage:       "ot segmentation",
				Handler:     otSegmentationHandler,
			},
			{
				Name:        "historian",
				Description: "Detect and assess historian/SCADA servers",
				Usage:       "ot historian",
				Handler:     otHistorianHandler,
			},
			{
				Name:        "estop",
				Description: "Emergency stop all OT operations",
				Usage:       "ot estop [--confirm]",
				Handler:     otEStopHandler,
			},
		},
	})
}

func otHelpHandler(ctx *console.Context, args []string) error {
	if !hasOTAccess(ctx) {
		return fmt.Errorf("access denied: ot.assess permission required")
	}

	w := console.NewWriter()
	w.Info("OT/ICS Assessment Module")
	w.Info("========================")
	w.Info("")
	w.Info("SAFETY: All operations are READ-ONLY.")
	w.Info("No writes, no firmware changes, no process manipulation.")
	w.Info("")
	w.Info("Commands:")
	w.Info("  ot discover     - Discover OT/ICS assets")
	w.Info("  ot scan         - Vulnerability scan (offline CVE correlation)")
	w.Info("  ot capture      - Passive traffic capture")
	w.Info("  ot topology     - Build Purdue model topology")
	w.Info("  ot compliance   - Compliance gap analysis")
	w.Info("  ot report       - Generate assessment report")
	w.Info("  ot creds        - Default credential check (1 attempt)")
	w.Info("  ot hmi          - HMI web interface assessment")
	w.Info("  ot wireless     - Wireless detection in OT zones")
	w.Info("  ot serial       - Serial port & fieldbus enumeration")
	w.Info("  ot plc          - PLC program metadata (read-only)")
	w.Info("  ot assets       - List discovered assets")
	w.Info("  ot segmentation - Network segmentation analysis")
	w.Info("  ot historian    - Historian/SCADA detection")
	w.Info("  ot estop        - Emergency stop all operations")

	return nil
}

func otDiscoverHandler(ctx *console.Context, args []string) error {
	if !hasOTAccess(ctx) {
		return fmt.Errorf("access denied: ot.assess permission required")
	}

	w := console.NewWriter()

	passive := hasFlag(args, "--passive")
	active := hasFlag(args, "--active")
	if !passive && !active {
		passive = true // Default to passive
	}

	if active {
		w.Warn("Active discovery will send probes to OT devices. Continue? (--confirm)")
	}

	w.Info("Starting OT discovery (passive=%v, active=%v)...", passive, active)
	w.Info("Stub: Would invoke implant OT discovery via gRPC task.")

	// Stub: Would create a task to run OT discovery on the active session
	table := console.NewTable(w, "IP", "Vendor", "Model", "Protocol", "Role", "Purdue Level")
	table.AddRow("(discovery not yet connected)")
	table.Render()

	return nil
}

func otScanHandler(ctx *console.Context, args []string) error {
	if !hasOTAccess(ctx) {
		return fmt.Errorf("access denied: ot.assess permission required")
	}
	if err := requireArg(args, 1, "ot scan <target-ip>"); err != nil {
		return err
	}

	target := args[0]
	w := console.NewWriter()
	w.Info("Scanning OT asset %s for vulnerabilities (offline CVE correlation)...", target)
	w.Info("Stub: Would invoke implant OT vulnerability scan via gRPC task.")

	return nil
}

func otCaptureHandler(ctx *console.Context, args []string) error {
	if !hasOTAccess(ctx) {
		return fmt.Errorf("access denied: ot.assess permission required")
	}

	w := console.NewWriter()
	w.Info("Starting passive OT traffic capture...")
	w.Info("Stub: Would invoke implant traffic capture via gRPC task.")

	return nil
}

func otTopologyHandler(ctx *console.Context, args []string) error {
	if !hasOTAccess(ctx) {
		return fmt.Errorf("access denied: ot.assess permission required")
	}

	format := "json"
	if idx := flagValue(args, "--format"); idx != "" {
		format = idx
	}

	w := console.NewWriter()
	w.Info("Building OT network topology (format=%s)...", format)
	w.Info("Stub: Would build topology from discovered assets.")

	return nil
}

func otComplianceHandler(ctx *console.Context, args []string) error {
	if !hasOTAccess(ctx) {
		return fmt.Errorf("access denied: ot.assess permission required")
	}

	framework := flagValue(args, "--framework")
	if framework == "" {
		framework = "iec62443"
	}

	w := console.NewWriter()
	w.Info("Running %s compliance gap analysis...", framework)
	w.Info("Stub: Would invoke compliance checker with assessment data.")

	return nil
}

func otReportHandler(ctx *console.Context, args []string) error {
	if !hasOTAccess(ctx) {
		return fmt.Errorf("access denied: ot.assess permission required")
	}

	format := "markdown"
	if f := flagValue(args, "--format"); f != "" {
		format = f
	}

	w := console.NewWriter()
	w.Info("Generating OT assessment report (format=%s)...", format)
	w.Info("Stub: Would gather all assessment data and generate report.")

	return nil
}

func otCredsHandler(ctx *console.Context, args []string) error {
	if !hasOTAccess(ctx) {
		return fmt.Errorf("access denied: ot.assess permission required")
	}
	if err := requireArg(args, 1, "ot creds <target-ip>"); err != nil {
		return err
	}

	target := args[0]
	w := console.NewWriter()
	w.Warn("SAFETY: Testing ONE default credential per service. No brute force.")
	w.Info("Testing default credentials on %s...", target)
	w.Info("Stub: Would invoke credential checker via gRPC task.")

	return nil
}

func otHMIHandler(ctx *console.Context, args []string) error {
	if !hasOTAccess(ctx) {
		return fmt.Errorf("access denied: ot.assess permission required")
	}
	if err := requireArg(args, 1, "ot hmi <target-ip>"); err != nil {
		return err
	}

	target := args[0]
	w := console.NewWriter()
	w.Info("Assessing HMI web interfaces on %s (HTTP GET only)...", target)
	w.Info("Stub: Would invoke HMI assessor via gRPC task.")

	return nil
}

func otWirelessHandler(ctx *console.Context, args []string) error {
	if !hasOTAccess(ctx) {
		return fmt.Errorf("access denied: ot.assess permission required")
	}

	w := console.NewWriter()
	w.Info("Detecting wireless presence in OT environment...")
	w.Info("Stub: Would invoke wireless scanner via gRPC task.")

	return nil
}

func otSerialHandler(ctx *console.Context, args []string) error {
	if !hasOTAccess(ctx) {
		return fmt.Errorf("access denied: ot.assess permission required")
	}

	w := console.NewWriter()
	w.Info("Enumerating serial ports and fieldbus gateways...")
	w.Info("Stub: Would invoke serial scanner via gRPC task.")

	return nil
}

func otPLCHandler(ctx *console.Context, args []string) error {
	if !hasOTAccess(ctx) {
		return fmt.Errorf("access denied: ot.assess permission required")
	}
	if err := requireArg(args, 1, "ot plc <target-ip>"); err != nil {
		return err
	}

	target := args[0]
	protocol := "s7"
	if p := flagValue(args, "--protocol"); p != "" {
		protocol = p
	}

	w := console.NewWriter()
	w.Info("Reading PLC program metadata from %s via %s (READ-ONLY)...", target, protocol)
	w.Info("Stub: Would invoke PLC logic reader via gRPC task.")

	return nil
}

func otAssetsHandler(ctx *console.Context, args []string) error {
	if !hasOTAccess(ctx) {
		return fmt.Errorf("access denied: ot.assess permission required")
	}

	w := console.NewWriter()
	w.Info("Listing discovered OT assets...")

	table := console.NewTable(w, "IP", "Vendor", "Model", "Role", "Purdue", "Protocols", "Safety")
	table.AddRow("(no assets discovered yet)")
	table.Render()

	return nil
}

func otSegmentationHandler(ctx *console.Context, args []string) error {
	if !hasOTAccess(ctx) {
		return fmt.Errorf("access denied: ot.assess permission required")
	}

	w := console.NewWriter()
	w.Info("Analyzing OT network segmentation...")
	w.Info("Stub: Would invoke segmentation analyzer via gRPC task.")

	return nil
}

func otHistorianHandler(ctx *console.Context, args []string) error {
	if !hasOTAccess(ctx) {
		return fmt.Errorf("access denied: ot.assess permission required")
	}

	w := console.NewWriter()
	w.Info("Detecting historian/SCADA servers...")
	w.Info("Stub: Would invoke historian detector via gRPC task.")

	return nil
}

func otEStopHandler(ctx *console.Context, args []string) error {
	if !hasOTAccess(ctx) {
		return fmt.Errorf("access denied: ot.assess permission required")
	}

	if !hasFlag(args, "--confirm") {
		w := console.NewWriter()
		w.Warn("WARNING: This will immediately stop ALL OT assessment operations.")
		w.Warn("Use 'ot estop --confirm' to execute.")
		return nil
	}

	w := console.NewWriter()
	w.Warn("EMERGENCY STOP activated. All OT operations halted.")
	w.Info("Stub: Would invoke OT emergency stop via gRPC.")

	return nil
}

// hasOTAccess checks if the operator has OT assessment permissions.
func hasOTAccess(ctx *console.Context) bool {
	// The ot-operator and admin roles have ot.assess permission.
	return ctx.OperatorRole == "admin" || ctx.OperatorRole == "ot-operator"
}

// hasFlag checks if a flag is present in the args.
func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// flagValue returns the value following a flag, or empty string.
func flagValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
