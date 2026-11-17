package web

import (
	"context"
	"net/http"
	"net/url"

	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
)

type notificationRetrier interface {
	RetryNotification(context.Context, string, string, string, string, string) error
}

func (a *App) handleNotificationRetry(w http.ResponseWriter, r *http.Request) {
	limitForm(w, r)
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	ctx, ok := a.deviceCommandIntent(w, r)
	if !ok {
		return
	}
	store, ok := a.profiles.(notificationRetrier)
	if !ok {
		http.Error(w, "Notification retry unavailable", 503)
		return
	}
	user := sessionFrom(r).Identity
	if err := store.RetryNotification(ctx, r.PathValue("id"), r.PathValue("uuid"), mdmcore.CommandIntent(ctx), user.Username, user.Provider); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	http.Redirect(w, r, "/admin/devices/"+url.PathEscape(r.PathValue("id"))+"?flash=Notification+retry+scheduled", 303)
}
