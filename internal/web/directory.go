package web

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

type DirectoryResolver interface {
	ResolveOwner(context.Context, string) (*auth.DirectoryIdentity, error)
	ResolveScope(context.Context, string, string, string) (*auth.DirectoryScope, error)
	EvaluateScopes(context.Context, auth.DirectoryIdentity, []auth.DirectoryScope) (*auth.DirectoryScopeEvaluation, error)
}
type directoryRuleStore interface {
	ListDirectoryProfileRules(context.Context) ([]sqlite.DirectoryProfileRule, error)
	SaveDirectoryProfileRule(context.Context, int64, auth.DirectoryScope, string, string) error
	DeleteDirectoryProfileRule(context.Context, int64, string, string) error
}

func (a *App) SetDirectory(d DirectoryResolver) { a.directory = d }

type directoryPreviewProfile struct {
	Profile sqlite.Profile
	Sources []string
}

func (a *App) directoryPage(w http.ResponseWriter, r *http.Request, status int, message string, extra map[string]any) {
	data := map[string]any{"Title": "Directory profile rules", "Error": message, "DirectoryReady": a.directory != nil}
	store, ok := a.groups.(directoryRuleStore)
	if !ok {
		http.Error(w, "Directory rules unavailable", 503)
		return
	}
	rules, err := store.ListDirectoryProfileRules(r.Context())
	if err != nil {
		http.Error(w, "Cannot load directory rules", 503)
		return
	}
	groups, err := a.groups.ListGroups(r.Context())
	if err != nil {
		http.Error(w, "Cannot load groups", 503)
		return
	}
	data["Rules"] = rules
	data["Groups"] = groups
	for k, v := range extra {
		data[k] = v
	}
	a.render(w, r, status, "directory.html", data)
}
func (a *App) handleDirectory(w http.ResponseWriter, r *http.Request) {
	a.directoryPage(w, r, 200, "", nil)
}
func (a *App) handleDirectorySave(w http.ResponseWriter, r *http.Request) {
	limitForm(w, r)
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	if a.directory == nil {
		a.directoryPage(w, r, 503, "Configure LDAP with a directory ID to resolve groups and OUs.", nil)
		return
	}
	groupID, err := strconv.ParseInt(r.PostFormValue("group_id"), 10, 64)
	if err != nil {
		a.directoryPage(w, r, 400, "Choose a Cairn group.", nil)
		return
	}
	if _, err = a.groups.GetGroup(r.Context(), groupID); err != nil {
		a.directoryPage(w, r, 400, "Choose an existing Cairn group.", nil)
		return
	}
	kind, mode, valid := strings.Cut(r.PostFormValue("scope"), ":")
	if !valid {
		a.directoryPage(w, r, 400, "Choose a directory scope.", nil)
		return
	}
	scope, err := a.directory.ResolveScope(r.Context(), kind, mode, strings.TrimSpace(r.PostFormValue("name")))
	if err != nil {
		a.directoryPage(w, r, 422, "Cannot resolve that directory object and membership mode. Use an exact name, or its full distinguished name if ambiguous.", nil)
		return
	}
	store, ok := a.groups.(directoryRuleStore)
	if !ok {
		http.Error(w, "Directory rules unavailable", 503)
		return
	}
	user := sessionFrom(r).Identity
	if err = store.SaveDirectoryProfileRule(r.Context(), groupID, *scope, user.Username, user.Provider); err != nil {
		a.directoryPage(w, r, 503, "The rule was not saved.", nil)
		return
	}
	http.Redirect(w, r, "/admin/directory", 303)
}
func (a *App) handleDirectoryDelete(w http.ResponseWriter, r *http.Request) {
	limitForm(w, r)
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	store, ok := a.groups.(directoryRuleStore)
	if !ok {
		http.Error(w, "Directory rules unavailable", 503)
		return
	}
	user := sessionFrom(r).Identity
	if err = store.DeleteDirectoryProfileRule(r.Context(), id, user.Username, user.Provider); err != nil {
		a.directoryPage(w, r, 409, "The rule was not deleted.", nil)
		return
	}
	http.Redirect(w, r, "/admin/directory", 303)
}
func (a *App) handleDirectoryPreview(w http.ResponseWriter, r *http.Request) {
	limitForm(w, r)
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	if a.directory == nil {
		a.directoryPage(w, r, 503, "Configure LDAP with a directory ID to preview assignments.", nil)
		return
	}
	store, ok := a.groups.(directoryRuleStore)
	if !ok {
		http.Error(w, "Directory rules unavailable", 503)
		return
	}
	rules, err := store.ListDirectoryProfileRules(r.Context())
	if err != nil {
		a.directoryPage(w, r, 503, "Cannot load rules.", nil)
		return
	}
	owner, err := a.directory.ResolveOwner(r.Context(), strings.TrimSpace(r.PostFormValue("account")))
	if err != nil {
		a.directoryPage(w, r, 422, "Cannot resolve an eligible directory user.", nil)
		return
	}
	scopes := make([]auth.DirectoryScope, len(rules))
	for i, rule := range rules {
		scopes[i] = rule.Scope
	}
	result, err := a.directory.EvaluateScopes(r.Context(), *owner, scopes)
	if err != nil || result == nil || len(result.Matches) != len(rules) {
		a.directoryPage(w, r, 503, "Directory preview unavailable. No assignments changed; retry after directory access is restored.", nil)
		return
	}
	profiles := []directoryPreviewProfile{}
	indices := map[int64]int{}
	identifiers := map[string]int64{}
	conflicts := []string{}
	for i, match := range result.Matches {
		if !match.Matches {
			continue
		}
		assigned, e := a.groups.GroupProfiles(r.Context(), rules[i].GroupID)
		if e != nil {
			a.directoryPage(w, r, 503, "Cannot read assigned profiles; preview is incomplete.", nil)
			return
		}
		for _, profile := range assigned {
			source := fmt.Sprintf("%s (%s: %s, %s)", rules[i].GroupName, match.Scope.Kind, match.Scope.Name, match.Scope.Mode)
			if idx, found := indices[profile.ID]; found {
				profiles[idx].Sources = append(profiles[idx].Sources, source)
				continue
			}
			if existing, found := identifiers[profile.Identifier]; found && existing != profile.ID {
				conflicts = append(conflicts, "Multiple profiles use identifier "+profile.Identifier)
			}
			identifiers[profile.Identifier] = profile.ID
			indices[profile.ID] = len(profiles)
			profiles = append(profiles, directoryPreviewProfile{Profile: profile, Sources: []string{source}})
		}
	}
	a.directoryPage(w, r, 200, "", map[string]any{"Evaluation": result, "PreviewProfiles": profiles, "Conflicts": conflicts})
}
