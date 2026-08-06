package web

import (
	"net/http"
)

// handleQuarantine lists quarantined certificate issuances — enrollments held after
// an ambiguous CA outcome (a response lost after the CA may have signed, a backend
// error, or a returned leaf that did not match the reconstructed intent). This is a
// read-only view for now; releasing a quarantine requires the evidence-gated
// resolution flow (fence → enumerate serials → confirm rejected at RADIUS), which
// lands with the ResolveQuarantine backend. There is deliberately no "release" button
// here yet, so nothing can free a held enrollment without that proof.
func (a *App) handleQuarantine(w http.ResponseWriter, r *http.Request) {
	items, err := a.quarantine.ListQuarantined(r.Context())
	if err != nil {
		a.log.Error("list quarantined", "err", err)
	}
	a.render(w, r, http.StatusOK, "quarantine.html", map[string]any{
		"Title": "Quarantine",
		"Items": items,
	})
}
