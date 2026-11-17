package mdmcore

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/service"
	"github.com/micromdm/plist"
)

// Lifecycle follows each device's identity certificate through renewal.
type Lifecycle interface {
	// Presented is told about every signed request before the certificate is
	// checked against the device's enrollment. It may associate a renewed
	// certificate with the device. The caller has proved only that it holds
	// the certificate's key, so nothing else may be recorded from it.
	Presented(ctx context.Context, deviceID string, cert *x509.Certificate)
	// CheckedIn is told about a request after its certificate was found to
	// belong to the device, with the host name the device used.
	CheckedIn(ctx context.Context, deviceID, host string)
	// RenewalCommand names the one command a device with an expired
	// certificate may be given, or "" when none is waiting.
	RenewalCommand(ctx context.Context, deviceID string) string
	// ProfileList receives a device's answer to a ProfileList command.
	ProfileList(ctx context.Context, deviceID, commandUUID string, profiles []InstalledProfile)
}

// InstalledProfile is one entry of a device's ProfileList answer.
type InstalledProfile struct {
	Identifier   string
	DisplayName  string
	Organization string
	PayloadTypes []string
}

// HasPayload reports whether the profile carries a payload of the given type.
func (p InstalledProfile) HasPayload(payloadType string) bool {
	for _, t := range p.PayloadTypes {
		if t == payloadType {
			return true
		}
	}
	return false
}

// profileListFromRaw extracts the installed profiles from a command result. It
// reports ok=false for any result that is not a ProfileList answer.
func profileListFromRaw(raw []byte) ([]InstalledProfile, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var top map[string]any
	if err := plist.Unmarshal(raw, &top); err != nil {
		return nil, false
	}
	list, ok := top["ProfileList"].([]any)
	if !ok {
		return nil, false
	}
	str := func(m map[string]any, k string) string {
		v, _ := m[k].(string)
		return v
	}
	out := make([]InstalledProfile, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		p := InstalledProfile{Identifier: str(m, "PayloadIdentifier"), DisplayName: str(m, "PayloadDisplayName"), Organization: str(m, "PayloadOrganization")}
		content, _ := m["PayloadContent"].([]any)
		for _, c := range content {
			if cm, ok := c.(map[string]any); ok {
				p.PayloadTypes = append(p.PayloadTypes, str(cm, "PayloadType"))
			}
		}
		out = append(out, p)
	}
	return out, true
}

type checkInHostKey struct{}

// checkInHost is the Host header of the device's request.
func checkInHost(ctx context.Context) string {
	v, _ := ctx.Value(checkInHostKey{}).(string)
	return v
}

type commandLimitKey struct{}

// WithCommandLimit restricts the request to one queued command. An empty UUID
// means the device is given nothing.
func WithCommandLimit(ctx context.Context, commandUUID string) context.Context {
	return context.WithValue(ctx, commandLimitKey{}, commandUUID)
}

// CommandLimit reports whether the request is restricted and to which command.
func CommandLimit(ctx context.Context) (commandUUID string, limited bool) {
	commandUUID, limited = ctx.Value(commandLimitKey{}).(string)
	return commandUUID, limited
}

// deviceOf returns the device an enrollment belongs to. A Mac's user channel
// shares the device's identity certificate, so it resolves to the device.
func deviceOf(e *mdm.Enrollment) string {
	if r := e.Resolved(); r != nil {
		return r.DeviceChannelID
	}
	return ""
}

// presenter tells the lifecycle which certificate each request arrived with.
// It sits outside certificate authorization so a renewed certificate can be
// associated before it is checked.
type presenter struct {
	next service.CheckinAndCommandService
	core *Core
}

func (p *presenter) present(r *mdm.Request, e *mdm.Enrollment) {
	l := p.core.lifecycle.Load()
	if l == nil || r.Certificate == nil {
		return
	}
	if id := deviceOf(e); id != "" {
		(*l).Presented(r.Context(), id, r.Certificate)
	}
}

func (p *presenter) Authenticate(r *mdm.Request, m *mdm.Authenticate) error {
	// Refused here, not in the gate: certificate authorization associates
	// whatever certificate an Authenticate arrives with.
	if r.Certificate != nil && p.core.now().After(r.Certificate.NotAfter) {
		return errRenewalOnly
	}
	p.present(r, &m.Enrollment)
	return p.next.Authenticate(r, m)
}
func (p *presenter) TokenUpdate(r *mdm.Request, m *mdm.TokenUpdate) error {
	p.present(r, &m.Enrollment)
	return p.next.TokenUpdate(r, m)
}
func (p *presenter) CheckOut(r *mdm.Request, m *mdm.CheckOut) error {
	p.present(r, &m.Enrollment)
	return p.next.CheckOut(r, m)
}
func (p *presenter) UserAuthenticate(r *mdm.Request, m *mdm.UserAuthenticate) ([]byte, error) {
	p.present(r, &m.Enrollment)
	return p.next.UserAuthenticate(r, m)
}
func (p *presenter) SetBootstrapToken(r *mdm.Request, m *mdm.SetBootstrapToken) error {
	p.present(r, &m.Enrollment)
	return p.next.SetBootstrapToken(r, m)
}
func (p *presenter) GetBootstrapToken(r *mdm.Request, m *mdm.GetBootstrapToken) (*mdm.BootstrapToken, error) {
	p.present(r, &m.Enrollment)
	return p.next.GetBootstrapToken(r, m)
}
func (p *presenter) DeclarativeManagement(r *mdm.Request, m *mdm.DeclarativeManagement) ([]byte, error) {
	p.present(r, &m.Enrollment)
	return p.next.DeclarativeManagement(r, m)
}
func (p *presenter) GetToken(r *mdm.Request, m *mdm.GetToken) (*mdm.GetTokenResponse, error) {
	p.present(r, &m.Enrollment)
	return p.next.GetToken(r, m)
}
func (p *presenter) CommandAndReportResults(r *mdm.Request, m *mdm.CommandResults) (*mdm.Command, error) {
	p.present(r, &m.Enrollment)
	return p.next.CommandAndReportResults(r, m)
}

// errRenewalOnly refuses everything an expired certificate is not allowed.
var errRenewalOnly = service.NewHTTPStatusError(http.StatusForbidden, errors.New("identity certificate expired: only renewal is allowed"))

// expiryGate limits a device whose identity certificate has expired but is
// still inside the grace period. It may report results, keep its push token
// current, check out, and be given the command that renews it. Nothing else
// reaches it until it presents a certificate that has not expired.
type expiryGate struct {
	next service.CheckinAndCommandService
	core *Core
}

func (g *expiryGate) expired(r *mdm.Request) bool {
	return r.Certificate != nil && g.core.now().After(r.Certificate.NotAfter)
}

// checkedIn reports the authorized request to the lifecycle.
func (g *expiryGate) checkedIn(r *mdm.Request, e *mdm.Enrollment) {
	if l := g.core.lifecycle.Load(); l != nil {
		if id := deviceOf(e); id != "" {
			(*l).CheckedIn(r.Context(), id, checkInHost(r.Context()))
		}
	}
}

func (g *expiryGate) Authenticate(r *mdm.Request, m *mdm.Authenticate) error {
	if g.expired(r) {
		return errRenewalOnly
	}
	return g.next.Authenticate(r, m)
}
func (g *expiryGate) TokenUpdate(r *mdm.Request, m *mdm.TokenUpdate) error {
	g.checkedIn(r, &m.Enrollment)
	return g.next.TokenUpdate(r, m)
}
func (g *expiryGate) CheckOut(r *mdm.Request, m *mdm.CheckOut) error {
	return g.next.CheckOut(r, m)
}
func (g *expiryGate) UserAuthenticate(r *mdm.Request, m *mdm.UserAuthenticate) ([]byte, error) {
	if g.expired(r) {
		return nil, errRenewalOnly
	}
	return g.next.UserAuthenticate(r, m)
}
func (g *expiryGate) SetBootstrapToken(r *mdm.Request, m *mdm.SetBootstrapToken) error {
	if g.expired(r) {
		return errRenewalOnly
	}
	return g.next.SetBootstrapToken(r, m)
}
func (g *expiryGate) GetBootstrapToken(r *mdm.Request, m *mdm.GetBootstrapToken) (*mdm.BootstrapToken, error) {
	if g.expired(r) {
		return nil, errRenewalOnly
	}
	return g.next.GetBootstrapToken(r, m)
}
func (g *expiryGate) DeclarativeManagement(r *mdm.Request, m *mdm.DeclarativeManagement) ([]byte, error) {
	if g.expired(r) {
		return nil, errRenewalOnly
	}
	return g.next.DeclarativeManagement(r, m)
}
func (g *expiryGate) GetToken(r *mdm.Request, m *mdm.GetToken) (*mdm.GetTokenResponse, error) {
	if g.expired(r) {
		return nil, errRenewalOnly
	}
	return g.next.GetToken(r, m)
}
func (g *expiryGate) CommandAndReportResults(r *mdm.Request, m *mdm.CommandResults) (*mdm.Command, error) {
	g.checkedIn(r, &m.Enrollment)
	if !g.expired(r) {
		return g.next.CommandAndReportResults(r, m)
	}
	only := ""
	// The renewal command is queued for the device, never for a user channel.
	if res := m.Enrollment.Resolved(); res != nil && !res.IsUserChannel {
		if l := g.core.lifecycle.Load(); l != nil {
			only = (*l).RenewalCommand(r.Context(), res.DeviceChannelID)
		}
	}
	return g.next.CommandAndReportResults(r.WithContext(WithCommandLimit(r.Context(), only)), m)
}
