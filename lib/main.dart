// Site Doctor — fine-grained website diagnostics.
//
// Stage 1 resolves the domain via the OS resolver (getaddrinfo) and lists
// every A/AAAA record. Stages 2-6 then run as N+1 independent suites:
//
//   Suite 0:   system-routed — the OS/DNS picks the server, exactly as a
//              browser would.
//   Suites 1..N: one per resolved address — the socket is dialed to that
//              specific server, while SNI and the Host header still carry
//              the domain name (the curl --resolve technique), so each
//              server is tested the way a browser would actually use it.
//
// Per suite:
//   2. TCP :80   3. TCP :443   4. TLS cert (presence, name, dates)
//   5. HTTP GET  6. HTTPS GET
//
// Zero external dependencies: dart:io + Flutter only.
// Targets: Windows, macOS, Linux, Android, iOS (not web: no raw sockets).

import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';

// Overridden by CI with the git tag: --dart-define=APP_VERSION=v1.1.0
const String appVersion =
    String.fromEnvironment('APP_VERSION', defaultValue: 'v1.1.0-dev');

void main() => runApp(const SiteDoctorApp());

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

enum StepStatus { pending, running, passed, warning, failed, skipped }

class DiagStep {
  DiagStep(this.title);
  final String title;
  StepStatus status = StepStatus.pending;
  String summary = '';
  final List<String> details = [];
  Duration? elapsed;

  void log(String line) => details.add(line);
}

/// One run of stages 2-6 against a single routing choice.
/// [targetIp] == null means "let the OS route" (suite 0).
class TestSuite {
  TestSuite(this.label, this.targetIp, String hostPathLabel) {
    httpGet = DiagStep('HTTP GET  http://$hostPathLabel');
    httpsGet = DiagStep('HTTPS GET  https://$hostPathLabel');
  }

  final String label;
  final String? targetIp;

  final DiagStep tcp80 = DiagStep('TCP connect — port 80 (HTTP)');
  final DiagStep tcp443 = DiagStep('TCP connect — port 443 (HTTPS)');
  final DiagStep tls = DiagStep('TLS handshake & certificate');
  late final DiagStep httpGet;
  late final DiagStep httpsGet;

  List<DiagStep> get steps => [tcp80, tcp443, tls, httpGet, httpsGet];
}

// ---------------------------------------------------------------------------
// Diagnostics engine
// ---------------------------------------------------------------------------

class Diagnostics {
  Diagnostics(this.host, this.pathAndQuery, this.onUpdate);

  final String host;
  final String pathAndQuery; // begins with '/', may include a query string
  final VoidCallback onUpdate;

  static const Duration _timeout = Duration(seconds: 10);

  late final DiagStep dns =
      DiagStep('DNS resolution (OS resolver, getaddrinfo)');
  final List<TestSuite> suites = [];

  String get _hostPathLabel =>
      pathAndQuery == '/' ? host : '$host$pathAndQuery';

  Future<void> run() async {
    dns.status = StepStatus.running;
    onUpdate();
    final sw = Stopwatch()..start();
    final addrs = await _testDns();
    dns.elapsed = (sw..stop()).elapsed;
    onUpdate();

    if (addrs.isEmpty) return; // DNS failed; nothing to route to.

    // Suite 0: OS-routed, then one suite per resolved server.
    suites.add(TestSuite(
        'System-routed — OS selects the server (browser behavior)',
        null,
        _hostPathLabel));
    for (final a in addrs) {
      final fam = a.type == InternetAddressType.IPv6 ? 'IPv6' : 'IPv4';
      suites.add(TestSuite('Server ${a.address} ($fam)', a.address,
          _hostPathLabel));
    }
    onUpdate();

    for (final suite in suites) {
      await _runSuite(suite);
    }
  }

  Future<void> _runSuite(TestSuite s) async {
    await _timed(s.tcp80, () => _testTcpPort(s, s.tcp80, 80));
    await _timed(s.tcp443, () => _testTcpPort(s, s.tcp443, 443));
    await _timed(s.tls, () => _testTls(s));
    await _timed(s.httpGet, () => _testHttpGet(s, secure: false));
    await _timed(s.httpsGet, () => _testHttpGet(s, secure: true));
  }

  Future<void> _timed(DiagStep step, Future<void> Function() body) async {
    step.status = StepStatus.running;
    onUpdate();
    final sw = Stopwatch()..start();
    try {
      await body();
    } catch (e) {
      step.status = StepStatus.failed;
      step.summary = 'Unexpected error: $e';
    }
    sw.stop();
    step.elapsed = sw.elapsed;
    onUpdate();
  }

  // -- 1. DNS ---------------------------------------------------------------
  //
  // InternetAddress.lookup() is Dart's wrapper around the platform's
  // getaddrinfo() — the OS host() resolution path (stub -> recursive ->
  // root/TLD/authoritative). The target web server is never contacted;
  // this stage purely verifies resource records exist for the name.

  Future<List<InternetAddress>> _testDns() async {
    try {
      final addrs = await InternetAddress.lookup(host).timeout(_timeout);
      if (addrs.isEmpty) {
        dns.status = StepStatus.failed;
        dns.summary = 'Lookup returned no resource records for "$host".';
        return [];
      }
      dns.log('Resolved via system resolver (getaddrinfo), '
          'not the target server.');
      final v4 = addrs.where((a) => a.type == InternetAddressType.IPv4);
      final v6 = addrs.where((a) => a.type == InternetAddressType.IPv6);
      for (final a in v4) {
        dns.log('A     ${a.address}');
      }
      for (final a in v6) {
        dns.log('AAAA  ${a.address}');
      }
      dns.status = StepStatus.passed;
      dns.summary = '${addrs.length} record(s): ${v4.length} A, '
          '${v6.length} AAAA — ${addrs.length} server(s) to test.';
      return addrs;
    } on SocketException catch (e) {
      dns.status = StepStatus.failed;
      dns.summary = 'No resource records — lookup failed.';
      dns.log('SocketException: ${e.message}');
      if (e.osError != null) dns.log('OS error: ${e.osError}');
    } on TimeoutException {
      dns.status = StepStatus.failed;
      dns.summary = 'Lookup timed out after ${_timeout.inSeconds}s.';
    }
    return [];
  }

  // -- 2 & 3. Raw TCP reachability -------------------------------------------

  Future<void> _testTcpPort(TestSuite s, DiagStep step, int port) async {
    final dialTo = s.targetIp ?? host;
    try {
      final socket = await Socket.connect(dialTo, port, timeout: _timeout);
      step.log('Connected to ${socket.remoteAddress.address}:'
          '${socket.remotePort} (local port ${socket.port})');
      socket.destroy();
      step.status = StepStatus.passed;
      step.summary = 'Server is listening on port $port.';
    } on SocketException catch (e) {
      step.status = StepStatus.failed;
      step.summary = 'Nothing answered on port $port.';
      step.log('SocketException: ${e.message}');
      if (e.osError != null) step.log('OS error: ${e.osError}');
    } on TimeoutException {
      step.status = StepStatus.failed;
      step.summary =
          'Connect timed out after ${_timeout.inSeconds}s (filtered or down).';
    }
  }

  // -- 4. TLS certificate ----------------------------------------------------
  //
  // Verifies exactly three things:
  //   (a) a certificate is presented,
  //   (b) it covers the host name being tested (SAN list, CN fallback),
  //   (c) it is date-valid right now.
  // Chain / CA trust is deliberately NOT evaluated.
  //
  // When targeting a specific server, the raw socket is dialed to that IP
  // and then upgraded to TLS with SNI = the domain name, so a virtual-host
  // server presents the same certificate a browser would receive from it.

  Future<void> _testTls(TestSuite s) async {
    if (s.tcp443.status == StepStatus.failed) {
      s.tls.status = StepStatus.skipped;
      s.tls.summary = 'Skipped — port 443 is not reachable.';
      return;
    }
    final tls = s.tls;

    X509Certificate? cert;
    try {
      final SecureSocket ss;
      if (s.targetIp == null) {
        ss = await SecureSocket.connect(host, 443,
            timeout: _timeout, onBadCertificate: (_) => true);
      } else {
        final raw =
            await Socket.connect(s.targetIp!, 443, timeout: _timeout);
        ss = await SecureSocket.secure(raw,
                host: host, onBadCertificate: (_) => true)
            .timeout(_timeout);
        tls.log('Dialed ${s.targetIp}; SNI sent as "$host".');
      }
      cert = ss.peerCertificate;
      ss.destroy();
    } on SocketException catch (e) {
      tls.status = StepStatus.failed;
      tls.summary = 'Could not open a TLS connection.';
      tls.log('SocketException: ${e.message}');
      return;
    } on HandshakeException catch (e) {
      tls.status = StepStatus.failed;
      tls.summary = 'TLS handshake failed — no certificate retrievable.';
      tls.log('HandshakeException: ${e.message}');
      return;
    } on TimeoutException {
      tls.status = StepStatus.failed;
      tls.summary = 'TLS handshake timed out after ${_timeout.inSeconds}s.';
      return;
    }

    if (cert == null) {
      tls.status = StepStatus.failed;
      tls.summary = 'Handshake completed but no certificate was presented.';
      return;
    }

    final sans = _extractDnsNames(cert.der);
    final cn =
        RegExp(r'CN=([^,/]+)').firstMatch(cert.subject)?.group(1)?.trim();
    final names = <String>{...sans, if (cn != null && cn.isNotEmpty) cn};
    final nameOk = names.any((n) => _nameMatches(host, n));

    final now = DateTime.now();
    final notBefore = cert.startValidity.toLocal();
    final notAfter = cert.endValidity.toLocal();
    final remaining = cert.endValidity.difference(now);
    final expiry = _fmtDate(notAfter);

    tls.log('Subject : ${cert.subject}');
    tls.log('Issuer  : ${cert.issuer}');
    tls.log('Names covered : '
        '${names.isEmpty ? '(none found)' : names.join(', ')}');
    tls.log('Valid from : ${_fmtDate(notBefore)}');
    tls.log('Expires    : $expiry');
    tls.log('Chain/CA trust intentionally not checked.');

    if (!nameOk) {
      tls.status = StepStatus.failed;
      tls.summary = 'Certificate does not cover "$host" '
          '(covers: ${names.isEmpty ? 'no names' : names.join(', ')}).';
    } else if (cert.startValidity.isAfter(now)) {
      tls.status = StepStatus.failed;
      tls.summary =
          'Certificate not yet valid (starts ${_fmtDate(notBefore)}).';
    } else if (remaining.isNegative) {
      tls.status = StepStatus.failed;
      tls.summary =
          'Certificate EXPIRED ${-remaining.inDays} day(s) ago ($expiry).';
    } else {
      tls.status = StepStatus.passed;
      tls.summary = 'Name matches; date-valid. Expires $expiry '
          '(${remaining.inDays} days left).';
    }
  }

  /// True if [host] is covered by certificate name [pattern]
  /// (exact match, or single-label wildcard like *.example.com).
  static bool _nameMatches(String host, String pattern) {
    host = host.toLowerCase();
    pattern = pattern.toLowerCase();
    if (pattern == host) return true;
    if (pattern.startsWith('*.')) {
      final dot = host.indexOf('.');
      return dot > 0 && host.substring(dot + 1) == pattern.substring(2);
    }
    return false;
  }

  /// Minimal DER walk: pull dNSName entries out of the subjectAltName
  /// extension (OID 2.5.29.17). No ASN.1 library — just enough parsing.
  static List<String> _extractDnsNames(List<int> der) {
    (int, int) len(int i) {
      final first = der[i];
      if (first < 0x80) return (first, 1);
      final n = first & 0x7F;
      var v = 0;
      for (var k = 0; k < n && i + 1 + k < der.length; k++) {
        v = (v << 8) | der[i + 1 + k];
      }
      return (v, 1 + n);
    }

    final names = <String>[];
    for (var i = 0; i + 4 < der.length; i++) {
      if (der[i] != 0x06 || der[i + 1] != 0x03 || der[i + 2] != 0x55 ||
          der[i + 3] != 0x1D || der[i + 4] != 0x11) continue;
      var j = i + 5;
      if (j + 2 < der.length && der[j] == 0x01 && der[j + 1] == 0x01) j += 3;
      if (j >= der.length || der[j] != 0x04) continue; // OCTET STRING
      final (_, oh) = len(j + 1);
      final k = j + 1 + oh;
      if (k >= der.length || der[k] != 0x30) continue; // SEQUENCE
      final (slen, sh) = len(k + 1);
      var p = k + 1 + sh;
      final end = p + slen;
      while (p < end && p + 1 < der.length) {
        final tag = der[p];
        final (l, h) = len(p + 1);
        final v = p + 1 + h;
        if (v + l > der.length) break;
        if (tag == 0x82) {
          names.add(String.fromCharCodes(der.sublist(v, v + l)));
        }
        p = v + l;
      }
      if (names.isNotEmpty) break;
    }
    return names;
  }

  // -- 5 & 6. Full HTTP / HTTPS GET -------------------------------------------
  //
  // When targeting a specific server, the connection is dialed to that IP
  // while the request URI keeps the domain name — so SNI, certificate
  // matching, the Host header, and redirects all behave exactly as a
  // browser reaching that particular server (curl --resolve equivalent).

  Future<void> _testHttpGet(TestSuite s, {required bool secure}) async {
    final step = secure ? s.httpsGet : s.httpGet;
    final dependency = secure ? s.tcp443 : s.tcp80;
    if (dependency.status == StepStatus.failed) {
      step.status = StepStatus.skipped;
      step.summary = 'Skipped — port ${secure ? 443 : 80} is not reachable.';
      return;
    }

    final client = HttpClient()
      ..connectionTimeout = _timeout
      ..userAgent = 'SiteDoctor/1.1';
    bool badCertAccepted = false;
    client.badCertificateCallback = (c, h, p) {
      badCertAccepted = true;
      return true;
    };
    if (s.targetIp != null) {
      final ip = s.targetIp!;
      client.connectionFactory = (uri, proxyHost, proxyPort) {
        // Dial the chosen server regardless of what the URI's host
        // resolves to. TLS (with SNI = uri.host) is layered on top by
        // HttpClient for https URIs.
        return Socket.startConnect(ip, uri.port);
      };
      step.log('Connections pinned to ${s.targetIp}.');
    }

    final parsed = Uri.parse('http://x$pathAndQuery');
    final uri = Uri(
      scheme: secure ? 'https' : 'http',
      host: host,
      path: parsed.path,
      query: parsed.query.isEmpty ? null : parsed.query,
    );

    try {
      final req = await client.getUrl(uri).timeout(_timeout);
      req.followRedirects = true;
      req.maxRedirects = 5;
      final resp = await req.close().timeout(_timeout);

      for (final r in resp.redirects) {
        step.log('Redirect ${r.statusCode} → ${r.location}');
      }

      int bytes = 0;
      await for (final chunk in resp.timeout(_timeout)) {
        bytes += chunk.length;
      }

      final server = resp.headers.value(HttpHeaders.serverHeader);
      final ctype = resp.headers.contentType?.toString();
      step.log('Status : ${resp.statusCode} ${resp.reasonPhrase}');
      if (server != null) step.log('Server : $server');
      if (ctype != null) step.log('Content-Type : $ctype');
      step.log('Body : $bytes bytes received');
      if (badCertAccepted) {
        step.log('FYI: OS did not trust the certificate; ignored — '
            'this stage only tests page delivery.');
      }

      final redirNote = resp.redirects.isEmpty
          ? ''
          : ' after ${resp.redirects.length} redirect(s)';
      if (resp.statusCode >= 200 && resp.statusCode < 300) {
        step.status = StepStatus.passed;
        step.summary = 'Page returned: ${resp.statusCode} '
            '${resp.reasonPhrase}, $bytes bytes$redirNote.';
      } else if (resp.statusCode >= 300 && resp.statusCode < 400) {
        step.status = StepStatus.warning;
        step.summary = 'Server answered with unfollowed redirect '
            '${resp.statusCode} ${resp.reasonPhrase}.';
      } else {
        step.status = StepStatus.failed;
        step.summary = 'Server answered, but with error '
            '${resp.statusCode} ${resp.reasonPhrase}$redirNote.';
      }
    } on HandshakeException catch (e) {
      step.status = StepStatus.failed;
      step.summary = 'TLS handshake failed — no page returned.';
      step.log('HandshakeException: ${e.message}');
    } on SocketException catch (e) {
      step.status = StepStatus.failed;
      step.summary = 'Connection failed — no page returned.';
      step.log('SocketException: ${e.message}');
    } on TimeoutException {
      step.status = StepStatus.failed;
      step.summary =
          'No response within ${_timeout.inSeconds}s — no page returned.';
    } on RedirectException catch (e) {
      step.status = StepStatus.failed;
      step.summary = 'Redirect loop or too many redirects (>5).';
      for (final r in e.redirects) {
        step.log('Redirect ${r.statusCode} → ${r.location}');
      }
    } finally {
      client.close(force: true);
    }
  }

  static String _fmtDate(DateTime d) {
    String two(int n) => n.toString().padLeft(2, '0');
    return '${d.year}-${two(d.month)}-${two(d.day)} '
        '${two(d.hour)}:${two(d.minute)} (local)';
  }
}

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

class SiteDoctorApp extends StatelessWidget {
  const SiteDoctorApp({super.key});

  @override
  Widget build(BuildContext context) {
    const seed = Color(0xFF1E6E5C);
    return MaterialApp(
      title: 'Site Doctor',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme:
            ColorScheme.fromSeed(seedColor: seed, brightness: Brightness.dark),
        useMaterial3: true,
        scaffoldBackgroundColor: const Color(0xFF15201D),
      ),
      home: const DiagnosticsPage(),
    );
  }
}

class DiagnosticsPage extends StatefulWidget {
  const DiagnosticsPage({super.key});
  @override
  State<DiagnosticsPage> createState() => _DiagnosticsPageState();
}

class _DiagnosticsPageState extends State<DiagnosticsPage> {
  final _controller = TextEditingController();
  Diagnostics? _diag;
  bool _running = false;
  String? _inputError;
  String? _targetLabel;

  Future<void> _run() async {
    final raw = _controller.text.trim();
    if (raw.isEmpty) {
      setState(() => _inputError = 'Enter a domain name or URL.');
      return;
    }
    final withScheme = raw.contains('://') ? raw : 'https://$raw';
    final Uri uri;
    try {
      uri = Uri.parse(withScheme);
    } catch (_) {
      setState(() => _inputError = 'Could not parse that as a URL.');
      return;
    }
    if (uri.host.isEmpty) {
      setState(() => _inputError = 'No host name found in the input.');
      return;
    }
    final pathAndQuery = (uri.path.isEmpty ? '/' : uri.path) +
        (uri.hasQuery ? '?${uri.query}' : '');

    final diag = Diagnostics(uri.host, pathAndQuery, () {
      if (mounted) setState(() {});
    });

    setState(() {
      _inputError = null;
      _running = true;
      _diag = diag;
      _targetLabel =
          pathAndQuery == '/' ? uri.host : '${uri.host}$pathAndQuery';
    });

    await diag.run();
    if (mounted) setState(() => _running = false);
  }

  @override
  Widget build(BuildContext context) {
    final diag = _diag;
    // Flatten DNS + suites into one scrollable list of rows.
    final rows = <Widget>[];
    if (diag != null) {
      rows.add(_StepCard(step: diag.dns, index: 1));
      for (final s in diag.suites) {
        rows.add(_SuiteHeader(label: s.label));
        var n = 2;
        for (final step in s.steps) {
          rows.add(_StepCard(step: step, index: n++));
        }
      }
    }

    return Scaffold(
      appBar: AppBar(
        title: const Text('Site Doctor',
            style: TextStyle(fontWeight: FontWeight.w600, letterSpacing: 1)),
        centerTitle: false,
        actions: [
          Center(
            child: Padding(
              padding: const EdgeInsets.only(right: 16),
              child: Text(appVersion,
                  style: TextStyle(
                      fontSize: 13,
                      fontFamily: 'monospace',
                      color: Theme.of(context).colorScheme.onSurfaceVariant)),
            ),
          ),
        ],
      ),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 760),
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: TextField(
                        controller: _controller,
                        enabled: !_running,
                        autocorrect: false,
                        keyboardType: TextInputType.url,
                        decoration: InputDecoration(
                          labelText: 'Domain or URL',
                          hintText:
                              'example.com  or  https://example.com/page',
                          errorText: _inputError,
                          border: const OutlineInputBorder(),
                        ),
                        onSubmitted: (_) => _running ? null : _run(),
                      ),
                    ),
                    const SizedBox(width: 12),
                    FilledButton.icon(
                      onPressed: _running ? null : _run,
                      icon: _running
                          ? const SizedBox(
                              width: 16,
                              height: 16,
                              child:
                                  CircularProgressIndicator(strokeWidth: 2))
                          : const Icon(Icons.monitor_heart_outlined),
                      label: Text(_running ? 'Testing…' : 'Run tests'),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                if (_targetLabel != null)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 4),
                    child: Text('Target: $_targetLabel',
                        style: TextStyle(
                            color: Theme.of(context)
                                .colorScheme
                                .onSurfaceVariant,
                            fontFamily: 'monospace')),
                  ),
                Expanded(
                  child: rows.isEmpty
                      ? Center(
                          child: Text(
                            'Enter a domain to run the checkup:\n'
                            'DNS, then per-server suites of\n'
                            'TCP 80 → TCP 443 → certificate → '
                            'HTTP GET → HTTPS GET',
                            textAlign: TextAlign.center,
                            style: TextStyle(
                                color: Theme.of(context)
                                    .colorScheme
                                    .onSurfaceVariant),
                          ),
                        )
                      : ListView(children: rows),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _SuiteHeader extends StatelessWidget {
  const _SuiteHeader({required this.label});
  final String label;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.fromLTRB(4, 18, 4, 6),
      child: Row(
        children: [
          Icon(Icons.dns_outlined, size: 18, color: cs.primary),
          const SizedBox(width: 8),
          Expanded(
            child: Text(label,
                style: TextStyle(
                    fontWeight: FontWeight.w600,
                    letterSpacing: 0.3,
                    color: cs.primary)),
          ),
        ],
      ),
    );
  }
}

class _StepCard extends StatelessWidget {
  const _StepCard({required this.step, required this.index});
  final DiagStep step;
  final int index;

  (IconData, Color) _iconFor(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    switch (step.status) {
      case StepStatus.pending:
        return (Icons.radio_button_unchecked, cs.outline);
      case StepStatus.running:
        return (Icons.sync, cs.primary);
      case StepStatus.passed:
        return (Icons.check_circle, const Color(0xFF63C593));
      case StepStatus.warning:
        return (Icons.warning_amber_rounded, const Color(0xFFE0B45C));
      case StepStatus.failed:
        return (Icons.cancel, const Color(0xFFE06C6C));
      case StepStatus.skipped:
        return (Icons.skip_next, cs.outline);
    }
  }

  @override
  Widget build(BuildContext context) {
    final (icon, color) = _iconFor(context);
    final elapsed =
        step.elapsed == null ? null : '${step.elapsed!.inMilliseconds} ms';

    return Card(
      margin: const EdgeInsets.symmetric(vertical: 4),
      child: step.details.isEmpty
          ? ListTile(
              leading: Icon(icon, color: color),
              title: Text('$index. ${step.title}'),
              subtitle: step.summary.isEmpty ? null : Text(step.summary),
              trailing: elapsed == null
                  ? null
                  : Text(elapsed,
                      style: TextStyle(
                          color: Theme.of(context).colorScheme.outline)),
            )
          : ExpansionTile(
              leading: Icon(icon, color: color),
              title: Text('$index. ${step.title}'),
              subtitle: Text(step.summary),
              trailing: elapsed == null
                  ? null
                  : Text(elapsed,
                      style: TextStyle(
                          color: Theme.of(context).colorScheme.outline)),
              childrenPadding: const EdgeInsets.fromLTRB(24, 0, 16, 12),
              expandedCrossAxisAlignment: CrossAxisAlignment.start,
              children: [
                for (final line in step.details)
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 2),
                    child: SelectableText(line,
                        style: const TextStyle(
                            fontFamily: 'monospace', fontSize: 13)),
                  ),
              ],
            ),
    );
  }
}
