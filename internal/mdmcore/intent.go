package mdmcore

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/plist"
)

type commandIntentKey struct{}

// WithCommandIntent scopes a caller's retry key. Web callers include their
// session and action; CLI callers must deliberately reuse an operation key.
func WithCommandIntent(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, commandIntentKey{}, key)
}
func CommandIntent(ctx context.Context) string {
	v, _ := ctx.Value(commandIntentKey{}).(string)
	return v
}

func applyCommandIntent(ctx context.Context, cmd *mdm.Command) error {
	key := CommandIntent(ctx)
	if key == "" {
		return nil
	}
	var raw map[string]any
	if err := plist.Unmarshal(cmd.Raw, &raw); err != nil {
		return err
	}
	hash := sha256.Sum256([]byte("cairn-command-intent-v1\x00" + key))
	hash[6] = (hash[6] & 0x0f) | 0x50
	hash[8] = (hash[8] & 0x3f) | 0x80
	raw["CommandUUID"] = fmt.Sprintf("%x-%x-%x-%x-%x", hash[:4], hash[4:6], hash[6:8], hash[8:10], hash[10:16])
	encoded, err := plist.Marshal(raw)
	if err != nil {
		return err
	}
	decoded, err := mdm.DecodeCommand(encoded)
	if err != nil {
		return err
	}
	*cmd = *decoded
	return nil
}
