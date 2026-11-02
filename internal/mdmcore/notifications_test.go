package mdmcore

import (
	"errors"
	"fmt"
	"github.com/micromdm/nanomdm/push/nanopush"
	"strings"
	"testing"
)

func TestPushErrorClassification(t *testing.T) {
	for _, reason := range []string{"BadDeviceToken", "DeviceTokenNotForTopic", "Forbidden", "ExpiredToken", "Unregistered", "PayloadTooLarge", "BadCertificate", "BadCertificateEnvironment"} {
		result := classifyPushError(fmt.Errorf("wrapped: %w", &nanopush.JSONPushError{Reason: reason}))
		if !result.StopRetry || !strings.Contains(result.Failure, reason) {
			t.Fatalf("%s: %+v", reason, result)
		}
	}
	for _, err := range []error{errors.New("sensitive token abc"), &nanopush.JSONPushError{Reason: "TooManyRequests"}, &nanopush.JSONPushError{Reason: "ServiceUnavailable"}, &nanopush.JSONPushError{Reason: "unrecognized sensitive token abc"}} {
		result := classifyPushError(err)
		if result.StopRetry || result.Failure == "" || strings.Contains(result.Failure, "abc") {
			t.Fatalf("unexpected outcome: %+v", result)
		}
	}
}
