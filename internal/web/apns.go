package web

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/nickpdawson/cairn-mdm/internal/push"
)

func (a *App) SetAPNS(m push.RequestManager, store push.CertificateStore) {
	a.apnsRequests = &m
	a.apnsCertificates = store
}

func (a *App) apnsAvailable(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if a.apnsRequests == nil || a.apnsCertificates == nil {
		http.Error(w, "APNs administration unavailable", 503)
		return false
	}
	return true
}

func (a *App) handleAPNS(w http.ResponseWriter, r *http.Request) {
	if !a.apnsAvailable(w, r) {
		return
	}
	topics, err := a.apnsTopics.ListAPNSTopics(r.Context())
	if err != nil {
		http.Error(w, "Unable to load certificates", 500)
		return
	}
	requests, err := a.apnsRequests.List()
	if err != nil {
		http.Error(w, "Unable to load saved requests", 500)
		return
	}
	a.render(w, r, 200, "apns.html", map[string]any{"Title": "APNs certificates", "Topics": topics, "Requests": requests})
}

func (a *App) apnsForm(w http.ResponseWriter, r *http.Request) bool {
	if !a.apnsAvailable(w, r) {
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var err error
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		err = r.ParseMultipartForm(2 << 20)
	} else {
		err = r.ParseForm()
	}
	if err != nil {
		http.Error(w, "Invalid form or upload too large (2 MiB maximum)", 400)
		return false
	}
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", 403)
		return false
	}
	if id := r.PathValue("id"); id != "" && !strings.HasSuffix(r.URL.Path, "/install") {
		receipt, err := a.apnsCertificates.APNSInstallReceipt(r.Context(), id)
		if err != nil {
			http.Error(w, "Unable to verify installation state", 503)
			return false
		}
		if receipt != nil {
			http.Error(w, "This request is already installed; create a new request for the next renewal", 409)
			return false
		}
	}
	return true
}

func (a *App) handleAPNSCreate(w http.ResponseWriter, r *http.Request) {
	if !a.apnsForm(w, r) {
		return
	}
	topic := r.PostFormValue("topic")
	if topic != "" {
		topics, err := a.apnsTopics.ListAPNSTopics(r.Context())
		if err != nil {
			http.Error(w, "Unable to load certificates", 500)
			return
		}
		found := false
		for _, v := range topics {
			if v.Topic == topic {
				found = true
			}
		}
		if !found {
			http.Error(w, "Select an existing topic to renew", 400)
			return
		}
	}
	account := strings.TrimSpace(r.PostFormValue("apple_account"))
	if len(account) > 254 {
		http.Error(w, "Apple Account reference too long", 400)
		return
	}
	req, err := a.apnsRequests.CreateForTopic(strings.TrimSpace(r.PostFormValue("email")), "US", "", topic, account)
	if err != nil {
		http.Error(w, "Unable to prepare request: "+err.Error(), 400)
		return
	}
	http.Redirect(w, r, "/admin/apns/requests/"+req.ID, http.StatusSeeOther)
}

func (a *App) renderAPNSRequest(w http.ResponseWriter, r *http.Request, status int, message string) {
	if !a.apnsAvailable(w, r) {
		return
	}
	id := r.PathValue("id")
	req, err := a.apnsRequests.Load(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_, err = a.apnsRequests.PublicArtifact(id, "push_request.plist")
	data := map[string]any{"Title": "APNs certificates", "Request": req, "Message": message, "Ready": err == nil}
	receipt, err := a.apnsCertificates.APNSInstallReceipt(r.Context(), id)
	if err != nil {
		http.Error(w, "Unable to verify installation state", 503)
		return
	}
	if receipt != nil {
		data["Receipt"] = receipt
		a.render(w, r, status, "apns_request.html", data)
		return
	}
	cert, err := a.apnsRequests.PublicArtifact(id, "certificate.pem")
	if err == nil {
		info, e := a.apnsRequests.Preview(id, cert)
		if e != nil {
			data["PreviewError"] = e.Error()
		} else {
			data["Preview"] = info
		}
	} else if !os.IsNotExist(err) {
		data["PreviewError"] = "Unable to read uploaded certificate"
	}
	a.render(w, r, status, "apns_request.html", data)
}

func (a *App) handleAPNSRequest(w http.ResponseWriter, r *http.Request) {
	a.renderAPNSRequest(w, r, 200, "")
}

func (a *App) handleAPNSSubmit(w http.ResponseWriter, r *http.Request) {
	if !a.apnsForm(w, r) {
		return
	}
	if err := a.apnsRequests.Submit(r.Context(), r.PathValue("id")); err != nil {
		a.renderAPNSRequest(w, r, 502, err.Error())
		return
	}
	a.renderAPNSRequest(w, r, 200, "Request submitted. Check your registered email for the encrypted attachment. Resubmitting uses the same keys and may send another email.")
}

func uploadedAPNSFile(r *http.Request) ([]byte, error) {
	f, _, err := r.FormFile("file")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, fmt.Errorf("file exceeds 1 MiB")
	}
	return b, nil
}

func (a *App) handleAPNSAttachment(w http.ResponseWriter, r *http.Request) {
	if !a.apnsForm(w, r) {
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	id := r.PathValue("id")
	b, err := uploadedAPNSFile(r)
	if err == nil {
		b, err = a.apnsRequests.Decrypt(id, b)
	}
	if err == nil {
		err = a.apnsRequests.SavePublicArtifact(id, "push_request.plist", b)
	}
	if err != nil {
		a.renderAPNSRequest(w, r, 400, "Attachment could not be saved: "+err.Error())
		return
	}
	http.Redirect(w, r, "/admin/apns/requests/"+id, 303)
}

func (a *App) handleAPNSDownload(w http.ResponseWriter, r *http.Request) {
	if !a.apnsAvailable(w, r) {
		return
	}
	b, err := a.apnsRequests.PublicArtifact(r.PathValue("id"), "push_request.plist")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="push_request.plist"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(b)
}

func (a *App) handleAPNSCertificate(w http.ResponseWriter, r *http.Request) {
	if !a.apnsForm(w, r) {
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	id := r.PathValue("id")
	b, err := uploadedAPNSFile(r)
	if err == nil {
		_, err = a.apnsRequests.Preview(id, b)
	}
	if err == nil {
		err = a.apnsRequests.SavePublicArtifact(id, "certificate.pem", b)
	}
	if err != nil {
		a.renderAPNSRequest(w, r, 400, "Certificate was not accepted: "+err.Error())
		return
	}
	http.Redirect(w, r, "/admin/apns/requests/"+id, 303)
}

func (a *App) handleAPNSInstall(w http.ResponseWriter, r *http.Request) {
	if !a.apnsForm(w, r) {
		return
	}
	sess := sessionFrom(r)
	_, err := a.apnsRequests.Install(r.Context(), a.apnsCertificates, r.PathValue("id"), r.PostFormValue("fingerprint"), sess.Identity.Username, sess.Identity.Provider, r.PostFormValue("make_default") == "yes")
	if err != nil {
		a.renderAPNSRequest(w, r, 409, "No certificate change was committed: "+err.Error())
		return
	}
	http.Redirect(w, r, "/admin/apns/requests/"+r.PathValue("id"), http.StatusSeeOther)
}
