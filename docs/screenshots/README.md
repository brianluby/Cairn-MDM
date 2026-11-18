# Screenshots

The pictures in the project README come from a throwaway server filled with an
invented fleet. Nothing in them is a real device, person or address. To retake
them after a console change (macOS, with Chrome and Node 22 or later):

```sh
d=$(mktemp -d)
go build -o "$d/cairn" ./cmd/cairn
"$d/cairn" init -config "$d/cairn.toml" -data-dir "$d" \
  -public-url https://mdm.example.org -tls proxy -admin-password "$DEMO_PW"
go run docs/screenshots/seed.go -db "$d/cairn.db"
```

Edit `$d/cairn.toml`: set `listen = "127.0.0.1:8459"`, add `[vpn]` with
`enabled = true`, and add an `[auth.ldap]` section with `directory_id`,
`enabled = true` and placeholder server, base DN, bind DN and password file.
The directory is never contacted; without it the VPN and Wi-Fi pages show a
warning instead of their buttons. Then:

```sh
"$d/cairn" serve -config "$d/cairn.toml" &
phone=/admin/devices/00008140-001A2B3C4D5E6F70
WIDTH=1440 HEIGHT=900 MAXH=2400 node docs/screenshots/shoot.mjs docs/screenshots \
  dashboard=/admin devices=/admin/devices "device=$phone#VPN..Command%20history" \
  group=/admin/groups/1 wifi=/admin/wifi enrollment=/admin/enrollment
```

Stop the server and delete `$d` afterwards.
