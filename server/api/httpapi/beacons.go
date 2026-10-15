package httpapi

import (
	"net/http"
	"time"

	"github.com/azizbinmohammad/private-c2/server/c2"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

// beaconHandler serves the portal's Beacons table.
//
// It reads from two places, because the durable one is empty in practice. The
// `beacons` table is the intended store, but nothing in the running server ever
// writes to it: the only writer, BeaconRepository in server/store/repository,
// is imported solely by server/api/grpc, and no gRPC server is ever
// constructed. Reading that table alone therefore returned a permanently empty
// list while implants were connected and checking in, which is what left the
// portal's Beacons panel blank.
//
// Live sessions are folded in from ImplantServer, which is where the connection
// path actually records implants (live state is held in memory, per
// docs/decisions.md). Persisting beacons to the table is tracked separately in
// TODO.md; once that lands the two sources overlap and the merge below keeps
// them from doubling up.
type beaconHandler struct {
	db            *gorm.DB
	implantServer *c2.ImplantServer
}

// beaconView is the row shape the portal's Beacons table renders. Field names
// match models.Beacon so persisted and live rows are indistinguishable to the
// UI, and decoding a response into []models.Beacon still works.
type beaconView struct {
	ID           string    `json:"id"`
	ImplantID    string    `json:"implant_id,omitempty"`
	Hostname     string    `json:"hostname"`
	Username     string    `json:"username"`
	OS           string    `json:"os"`
	Arch         string    `json:"arch"`
	RemoteAddr   string    `json:"remote_addr,omitempty"`
	Transport    string    `json:"transport,omitempty"`
	EngagementID string    `json:"engagement_id,omitempty"`
	LastCheckin  time.Time `json:"last_checkin,omitempty"`
	CreatedAt    time.Time `json:"created_at,omitempty"`

	// The beacon cadence is not reported. The implant never tells the server
	// what it actually uses: register_ack's Interval is invented server-side and
	// cmd/implant ignores it, taking its own --interval/--jitter instead. These
	// stay zero (and the portal renders an em dash) rather than reporting a
	// cadence that would be a fabrication. See docs/known-issues.md.
	IntervalMs  int64     `json:"interval_ms,omitempty"`
	JitterPct   int       `json:"jitter_pct,omitempty"`
	NextCheckin time.Time `json:"next_checkin,omitempty"`
}

func (bh *beaconHandler) handleBeacons(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		return
	}

	var stored []models.Beacon
	if err := bh.db.Find(&stored).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	live := bh.implantServer.ListSessions()
	beacons := make([]beaconView, 0, len(stored)+len(live))

	// A persisted row is already represented by a live session when they share
	// an implant ID. The live session is the truthful one -- it is what the
	// connection path is actually maintaining right now, while the stored row
	// is whatever was last written, so index the live sessions first and drop
	// the stored row that duplicates one. Doing it the other way round lets a
	// stale row outrank the session currently checking in.
	connected := make(map[string]bool, len(live))
	for _, s := range live {
		if s.ImplantID != "" {
			connected[s.ImplantID] = true
		}
	}

	for _, b := range stored {
		if b.ImplantID != "" && connected[b.ImplantID] {
			continue
		}
		beacons = append(beacons, beaconView{
			ID:           b.ID,
			ImplantID:    b.ImplantID,
			Hostname:     b.Hostname,
			Username:     b.Username,
			OS:           b.OS,
			Arch:         b.Arch,
			RemoteAddr:   b.RemoteAddr,
			Transport:    b.Transport,
			EngagementID: b.EngagementID,
			LastCheckin:  b.LastCheckin,
			CreatedAt:    b.CreatedAt,
			IntervalMs:   b.IntervalMs,
			JitterPct:    b.JitterPct,
			NextCheckin:  b.NextCheckin,
		})
	}

	for _, s := range live {
		beacons = append(beacons, beaconView{
			ID:          s.ID,
			ImplantID:   s.ImplantID,
			Hostname:    s.Hostname,
			Username:    s.Username,
			OS:          s.OS,
			Arch:        s.Arch,
			RemoteAddr:  s.RemoteAddr,
			Transport:   s.Transport,
			LastCheckin: s.LastCheckin,
			CreatedAt:   s.CreatedAt,
		})
	}

	writeJSON(w, http.StatusOK, beacons)
}
