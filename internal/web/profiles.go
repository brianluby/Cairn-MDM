package web

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/nickpdawson/cairn-mdm/internal/profile"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// maxProfileBytes bounds an uploaded .mobileconfig. Real profiles are a few KB;
// 2 MiB leaves room for embedded certificates and fonts.
const maxProfileBytes = 2 << 20

func (a *App) handleProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := a.profiles.ListProfiles(r.Context())
	if err != nil {
		a.log.Error("list profiles", "err", err)
	}
	a.render(w, r, http.StatusOK, "profiles.html", map[string]any{
		"Title":    "Profiles",
		"Profiles": profiles,
		"Flash":    r.URL.Query().Get("flash"),
		"Error":    r.URL.Query().Get("error"),
	})
}

func (a *App) handleProfileUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxProfileBytes)
	if err := r.ParseMultipartForm(maxProfileBytes); err != nil {
		a.redirectProfiles(w, r, "", "Upload too large or malformed.")
		return
	}
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	f, _, err := r.FormFile("profile")
	if err != nil {
		a.redirectProfiles(w, r, "", "Choose a .mobileconfig file to upload.")
		return
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		a.redirectProfiles(w, r, "", "Reading the upload failed.")
		return
	}

	info, err := profile.ParseInfo(data)
	if err != nil {
		a.log.Info("profile upload rejected", "err", err)
		a.redirectProfiles(w, r, "", "Not a valid configuration profile: "+err.Error())
		return
	}

	id, err := a.profiles.SaveProfile(r.Context(), sqlite.Profile{
		Identifier:   info.Identifier,
		UUID:         info.UUID,
		Name:         info.Name,
		Organization: info.Organization,
		PayloadTypes: strings.Join(info.PayloadTypes, ","),
		Source:       "upload",
		Data:         data,
	})
	if err != nil {
		a.log.Error("save profile", "identifier", info.Identifier, "err", err)
		a.redirectProfiles(w, r, "", "Saving the profile failed.")
		return
	}
	a.log.Info("profile saved", "id", id, "identifier", info.Identifier, "user", sessionFrom(r).Identity.Username)
	http.Redirect(w, r, "/admin/profiles/"+strconv.FormatInt(id, 10)+"?flash="+url.QueryEscape("Profile saved."), http.StatusSeeOther)
}

func (a *App) handleProfileDetail(w http.ResponseWriter, r *http.Request) {
	p, ok := a.profileFromPath(w, r)
	if !ok {
		return
	}
	deploys, err := a.deploys.ProfileDeploys(r.Context(), p.ID)
	if err != nil {
		a.log.Error("profile deploys", "id", p.ID, "err", err)
	}
	var groups []sqlite.Group
	if ps, ok := a.profiles.(profileAssignmentSource); ok {
		if groups, err = ps.ProfileGroups(r.Context(), p.ID); err != nil {
			a.log.Error("profile groups", "id", p.ID, "err", err)
		}
	}
	installed := 0
	for _, d := range deploys {
		if d.Status == "installed" {
			installed++
		}
	}
	a.render(w, r, http.StatusOK, "profile.html", map[string]any{
		"Title":     p.Name,
		"Profile":   p,
		"Size":      len(p.Data),
		"Deploys":   deploys,
		"Groups":    groups,
		"Installed": installed,
		"Affects":   p.Affects(),
		"Flash":     r.URL.Query().Get("flash"),
		"Error":     r.URL.Query().Get("error"),
	})
}

// profileAssignmentSource is the optional capability behind the profile page's
// group list and the delete gate.
type profileAssignmentSource interface {
	ProfileGroups(ctx context.Context, profileID int64) ([]sqlite.Group, error)
}

func (a *App) handleProfileDownload(w http.ResponseWriter, r *http.Request) {
	p, ok := a.profileFromPath(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFilename(p.Name)+`.mobileconfig"`)
	_, _ = w.Write(p.Data)
}

func (a *App) handleProfileDelete(w http.ResponseWriter, r *http.Request) {
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	p, ok := a.profileFromPath(w, r)
	if !ok {
		return
	}
	back := "/admin/profiles/" + strconv.FormatInt(p.ID, 10)
	// A profile still assigned to a group would be re-pushed to new members; the
	// library deletion must not quietly remove that intent. Unassign first.
	if ps, ok := a.profiles.(profileAssignmentSource); ok {
		if groups, err := ps.ProfileGroups(r.Context(), p.ID); err == nil && len(groups) > 0 {
			names := make([]string, 0, len(groups))
			for _, g := range groups {
				names = append(names, g.Name)
			}
			http.Redirect(w, r, back+"?error="+url.QueryEscape("Still assigned to: "+strings.Join(names, ", ")+". Unassign it from those groups first, then delete."), http.StatusSeeOther)
			return
		}
	}
	// Deleting while devices report it installed drops Cairn's record of those
	// installations (the devices keep the profile). Require an explicit acknowledgement.
	if deploys, err := a.deploys.ProfileDeploys(r.Context(), p.ID); err == nil && len(deploys) > 0 && r.PostFormValue("acknowledge") != "yes" {
		http.Redirect(w, r, back+"?error="+url.QueryEscape("This profile is recorded on "+strconv.Itoa(len(deploys))+" device(s). Tick the acknowledgement to delete the library entry; installed copies stay on devices until removed from each device page."), http.StatusSeeOther)
		return
	}
	if err := a.profiles.DeleteProfile(r.Context(), p.ID); err != nil {
		a.log.Error("delete profile", "id", p.ID, "err", err)
		a.redirectProfiles(w, r, "", "Deleting the profile failed.")
		return
	}
	a.log.Info("profile deleted", "id", p.ID, "identifier", p.Identifier, "user", sessionFrom(r).Identity.Username)
	a.redirectProfiles(w, r, "Profile removed from the library. Devices that have it keep it until a RemoveProfile command is sent.", "")
}

// profileFromPath loads the {id} profile or renders a 404.
func (a *App) profileFromPath(w http.ResponseWriter, r *http.Request) (sqlite.Profile, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		var p sqlite.Profile
		p, err = a.profiles.GetProfile(r.Context(), id)
		if err == nil {
			return p, true
		}
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, strconv.ErrSyntax) {
		a.log.Error("get profile", "err", err)
	}
	a.render(w, r, http.StatusNotFound, "error.html", map[string]any{
		"Title": "Not found", "Message": "No such profile.",
	})
	return sqlite.Profile{}, false
}

func (a *App) redirectProfiles(w http.ResponseWriter, r *http.Request, flash, errMsg string) {
	q := url.Values{}
	if flash != "" {
		q.Set("flash", flash)
	}
	if errMsg != "" {
		q.Set("error", errMsg)
	}
	http.Redirect(w, r, "/admin/profiles?"+q.Encode(), http.StatusSeeOther)
}

// sanitizeFilename keeps download filenames header-safe.
func sanitizeFilename(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		case r == ' ':
			return '_'
		default:
			return -1
		}
	}, s)
}
