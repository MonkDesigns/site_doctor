# Site Doctor

Fine-grained website diagnostics in Flutter. Enter a bare domain
(`example.com`) or a specific page (`https://example.com/status?x=1`) and it
runs a six-stage pipeline, stopping only where a failure makes later stages
meaningless:

1. **DNS resolution** — resolves the name through the **OS resolver**
   (`InternetAddress.lookup`, Dart's wrapper around `getaddrinfo()`, the same
   path a `host`/`nslookup` invocation takes: stub resolver → recursive
   resolver → root/TLD/authoritative servers). The target web server is never
   contacted in this stage; it purely verifies that resource records exist
   for the domain in public DNS. Lists every A/AAAA record returned, or the
   exact resolver error. All later stages are skipped if this fails.
2. **TCP connect, port 80** — raw socket connect; reports the remote address
   answered, or the OS-level error (refused vs. timeout tells you filtered
   vs. down).
3. **TCP connect, port 443** — same, for the HTTPS port.
4. **TLS handshake & certificate** — first a *strict* handshake (what a
   browser would see). If the chain fails validation it retries permissively
   so it can still show you the certificate. Reports subject, issuer,
   not-before, and **expiration date** with days remaining. Warns under
   30 days; fails on expired or invalid chain.
5. **HTTP GET** — full request to the path you gave (default `/`). Reports
   status code, redirect chain (up to 5 followed), Server header,
   Content-Type, body byte count, and timing.
6. **HTTPS GET** — same over TLS. If the cert is bad, the request is forced
   through anyway and flagged, so you can distinguish "cert problem" from
   "server problem".

Stages 5/6 are skipped when their port didn't answer in stages 2/3, so a
skip vs. fail distinction is itself diagnostic. Every stage shows elapsed
milliseconds; expandable rows hold the raw detail lines (selectable for
copy/paste).

## Build & run

No third-party packages — `dart:io` and Flutter only.

```sh
cd site_doctor
flutter create . --platforms=windows,macos,linux,android,ios  # generates platform shells
flutter run -d windows   # or: macos, linux, or a connected device
```

`flutter create .` fills in the platform folders around the provided
`lib/main.dart` and `pubspec.yaml` without touching them.

### Platform notes

- **Not the web target.** Browsers don't expose raw sockets or DNS, so
  stages 1–4 are impossible there. Everything else (Windows, macOS, Linux,
  Android, iOS) works.
- **macOS:** the sandbox blocks networking by default. Add the client
  entitlement to both `macos/Runner/DebugProfile.entitlements` and
  `macos/Runner/Release.entitlements`:
  ```xml
  <key>com.apple.security.network.client</key>
  <true/>
  ```
- **Android:** `flutter create` already adds the `INTERNET` permission for
  debug builds; for release builds confirm
  `<uses-permission android:name="android.permission.INTERNET"/>` is in
  `android/app/src/main/AndroidManifest.xml`.

## Tuning

- Per-stage timeout is the `_timeout` constant in `Diagnostics` (10 s).
- Redirect follow limit is `maxRedirects = 5` in `_testHttpGet`.
- The cert-expiry warning threshold is the `remaining.inDays < 30` check
  in `_testTls`.
