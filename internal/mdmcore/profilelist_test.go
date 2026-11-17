package mdmcore

import "testing"

func TestProfileListReadsWhetherAProfileIsManaged(t *testing.T) {
	raw := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CommandUUID</key><string>x</string><key>Status</key><string>Acknowledged</string>
<key>ProfileList</key><array>
  <dict><key>PayloadIdentifier</key><string>org.example.wifi</string><key>PayloadDisplayName</key><string>Wi-Fi</string>
    <key>IsManaged</key><true/>
    <key>PayloadContent</key><array><dict><key>PayloadType</key><string>com.apple.wifi.managed</string></dict></array></dict>
  <dict><key>PayloadIdentifier</key><string>org.example.byhand</string><key>IsManaged</key><false/></dict>
</array></dict></plist>`)
	list, ok := profileListFromRaw(raw)
	if !ok || len(list) != 2 {
		t.Fatalf("profiles = %v, ok = %v", list, ok)
	}
	if !list[0].Managed || list[0].Identifier != "org.example.wifi" || !list[0].HasPayload("com.apple.wifi.managed") || list[1].Managed {
		t.Fatalf("profiles = %+v", list)
	}
}
