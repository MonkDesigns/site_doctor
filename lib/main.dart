// Site Doctor — fine-grained website diagnostics.
//
// Runs a staged pipeline against a domain or URL:
//   1. DNS resolution        (which resource records came back)
//   2. TCP :80 reachability  (does anything answer on the HTTP port)
//   3. TCP :443 reachability (does anything answer on the HTTPS port)
//   4. TLS handshake + cert  (chain validity, subject/issuer, expiration)
//   5. HTTP GET              (status, redirects, bytes, timing)
//   6. HTTPS GET             (status, redirects, bytes, timing)
//
// Zero external dependencies: dart:io + Flutter only.
// Targets: Windows, macOS, Linux, Android, iOS.
// (Not the web target — browsers don't allow raw sockets/DNS.)

import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';

// Overridden by CI with the git tag: --dart-define=APP_VERSION=v1.0.2
const String appVersion =
    String.fromEnvironment('APP_VERSION', defaultValue: 'v1.0.2-dev');

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
  late final DiagStep tcp80 = DiagStep('TCP connect — port 80 (HTTP)');
  late final DiagStep tcp443 = DiagStep('TCP connect — port 443 (HTTPS)');
  late final DiagStep tls = DiagStep('TLS handshake & certificate');
  late final DiagStep httpGet = DiagStep('HTTP GET  http://$_hostPathLabel');
  late final DiagStep httpsGet = DiagStep('HTTPS GET  https://$_hostPathLabel');

  String get _hostPathLabel =>
      pathAndQuery == '/' ? host : '$host$pathAndQuery';

  List<DiagStep> get steps => [dns, tcp80, tcp443, tls, httpGet, httpsGet];

  bool _dnsOk = false;

  Future<void> run() async {
    await _timed(dns, _testDns);
    if (!_dnsOk) {
      for (final s in [tcp80, tcp443, tls, httpGet, httpsGet]) {
        s.status = StepStatus.skipped;
        s.summary = 'Skipped — DNS resolution failed, nothing to connect to.';
      }
      onUpdate();
      return;
    }
    await _timed(tcp80, _testTcp80);
    await _timed(tcp443, _testTcp443);
    await _timed(tls, _testTls);
    await _timed(httpGet, () => _testHttpGet(secure: false, step: httpGet));
    await _timed(httpsGet, () => _testHttpGet(secure: true, step: httpsGet));
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
  // getaddrinfo() — i.e. the OS host() resolution path. It queries the
  // system-configured resolver (stub -> recursive -> root/TLD/authoritative
  // hierarchy). Nothing here ever contacts the target web server; this stage
  // purely verifies that resource records exist for the name in public DNS
  // as seen from this machine.

  Future<void> _testDns() async {
    try {
      final addrs =
          await InternetAddress.lookup(host).timeout(_timeout);
      if (addrs.isEmpty) {
        dns.status = StepStatus.failed;
        dns.summary = 'Lookup returned no resource records for "$host".';
        return;
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
      dns.summary =
          '${addrs.length} record(s): ${v4.length} A, ${v6.length} AAAA.';
      _dnsOk = true;
    } on SocketException catch (e) {
      dns.status = StepStatus.failed;
      dns.summary = 'No resource records — lookup failed.';
      dns.log('SocketException: ${e.message}');
      if (e.osError != null) dns.log('OS error: ${e.osError}');
    } on TimeoutException {
      dns.status = StepStatus.failed;
      dns.summary = 'Lookup timed out after ${_timeout.inSeconds}s.';
    }
  }

  // -- 2 & 3. Raw TCP reachability -------------------------------------------

  Future<void> _testTcpPort(DiagStep step, int port) async {
    try {
      final socket =
          await Socket.connect(host, port, timeout: _timeout);
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

  Future<void> _testTcp80() => _testTcpPort(tcp80, 80);
  Future<void> _testTcp443() => _testTcpPort(tcp443, 443);

  // -- 4. TLS handshake & certificate ----------------------------------------

  Future<void> _testTls() async {
    if (tcp443.status == StepStatus.failed) {
      tls.status = StepStatus.skipped;
      tls.summary = 'Skipped — port 443 is not reachable.';
      return;
    }

    X509Certificate? cert;
    bool strictOk = false;
    String? strictError;

    // First pass: strict validation, the way a browser would see it.
    try {
      final s = await SecureSocket.connect(host, 443, timeout: _timeout);
      cert = s.peerCertificate;
      strictOk = true;
      s.destroy();
    } on HandshakeException catch (e) {
      strictError = e.message;
    } on TlsException catch (e) {
      strictError = e.message;
    } on SocketException catch (e) {
      tls.status = StepStatus.failed;
      tls.summary = 'Could not open a TLS connection.';
      tls.log('SocketException: ${e.message}');
      return;
    } on TimeoutException {
      tls.status = StepStatus.failed;
      tls.summary = 'TLS handshake timed out after ${_timeout.inSeconds}s.';
      return;
    }

    // Second pass (only if strict failed): fetch the cert anyway so we can
    // still report subject/issuer/expiry for debugging.
    if (!strictOk) {
      try {
        final s = await SecureSocket.connect(host, 443,
            timeout: _timeout, onBadCertificate: (_) => true);
        cert = s.peerCertificate;
        s.destroy();
      } catch (e) {
        tls.status = StepStatus.failed;
        tls.summary = 'TLS handshake failed; certificate not retrievable.';
        tls.log('Strict handshake error: $strictError');
        tls.log('Permissive retry error: $e');
        return;
      }
    }

    if (cert == null) {
      tls.status = StepStatus.failed;
      tls.summary = 'Handshake completed but no certificate was presented.';
      return;
    }

    final now = DateTime.now();
    final notBefore = cert.startValidity.toLocal();
    final notAfter = cert.endValidity.toLocal();
    final remaining = cert.endValidity.difference(now);

    tls.log('Subject : ${cert.subject}');
    tls.log('Issuer  : ${cert.issuer}');
    tls.log('Valid from : ${_fmtDate(notBefore)}');
    tls.log('Expires    : ${_fmtDate(notAfter)}');
    if (!strictOk) tls.log('Chain validation error: $strictError');

    final expiry = _fmtDate(notAfter);
    if (remaining.isNegative) {
      tls.status = StepStatus.failed;
      tls.summary =
          'Certificate EXPIRED ${-remaining.inDays} day(s) ago ($expiry).';
    } else if (!strictOk) {
      tls.status = StepStatus.failed;
      tls.summary =
          'Certificate presented but failed validation (expires $expiry).';
    } else if (cert.startValidity.isAfter(now)) {
      tls.status = StepStatus.warning;
      tls.summary = 'Certificate is not yet valid (starts '
          '${_fmtDate(notBefore)}).';
    } else if (remaining.inDays < 30) {
      tls.status = StepStatus.warning;
      tls.summary =
          'Certificate valid but expires in ${remaining.inDays} day(s): '
          '$expiry.';
    } else {
      tls.status = StepStatus.passed;
      tls.summary =
          'Certificate valid. Expires $expiry (${remaining.inDays} days left).';
    }
  }

  // -- 5 & 6. Full HTTP / HTTPS GET -------------------------------------------

  Future<void> _testHttpGet(
      {required bool secure, required DiagStep step}) async {
    final dependency = secure ? tcp443 : tcp80;
    if (dependency.status == StepStatus.failed) {
      step.status = StepStatus.skipped;
      step.summary =
          'Skipped — port ${secure ? 443 : 80} is not reachable.';
      return;
    }

    final client = HttpClient()
      ..connectionTimeout = _timeout
      ..userAgent = 'SiteDoctor/1.0';
    bool badCertAccepted = false;
    client.badCertificateCallback = (c, h, p) {
      badCertAccepted = true; // let the request proceed, but report it
      return true;
    };

    final uri = Uri(
      scheme: secure ? 'https' : 'http',
      host: host,
      path: Uri.parse('http://x$pathAndQuery').path,
      query: Uri.parse('http://x$pathAndQuery').query.isEmpty
          ? null
          : Uri.parse('http://x$pathAndQuery').query,
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
        step.log('NOTE: TLS certificate failed validation; '
            'request forced through for diagnostics.');
      }

      final redirNote = resp.redirects.isEmpty
          ? ''
          : ' after ${resp.redirects.length} redirect(s)';
      if (resp.statusCode >= 200 && resp.statusCode < 300) {
        step.status =
            badCertAccepted ? StepStatus.warning : StepStatus.passed;
        step.summary = 'Page returned: ${resp.statusCode} '
            '${resp.reasonPhrase}, $bytes bytes$redirNote'
            '${badCertAccepted ? ' (bad certificate!)' : ''}.';
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
    const seed = Color(0xFF1E6E5C); // desaturated spruce green
    return MaterialApp(
      title: 'Site Doctor',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
            seedColor: seed, brightness: Brightness.dark),
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
      _targetLabel = pathAndQuery == '/'
          ? uri.host
          : '${uri.host}$pathAndQuery';
    });

    await diag.run();
    if (mounted) setState(() => _running = false);
  }

  @override
  Widget build(BuildContext context) {
    final steps = _diag?.steps ?? const <DiagStep>[];
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
                      color:
                          Theme.of(context).colorScheme.onSurfaceVariant)),
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
                  child: steps.isEmpty
                      ? Center(
                          child: Text(
                            'Enter a domain to run the six-stage checkup:\n'
                            'DNS → TCP 80 → TCP 443 → certificate → '
                            'HTTP GET → HTTPS GET',
                            textAlign: TextAlign.center,
                            style: TextStyle(
                                color: Theme.of(context)
                                    .colorScheme
                                    .onSurfaceVariant),
                          ),
                        )
                      : ListView.builder(
                          itemCount: steps.length,
                          itemBuilder: (context, i) =>
                              _StepCard(step: steps[i], index: i + 1),
                        ),
                ),
              ],
            ),
          ),
        ),
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
    final elapsed = step.elapsed == null
        ? null
        : '${step.elapsed!.inMilliseconds} ms';

    return Card(
      margin: const EdgeInsets.symmetric(vertical: 4),
      child: step.details.isEmpty
          ? ListTile(
              leading: Icon(icon, color: color),
              title: Text('$index. ${step.title}'),
              subtitle:
                  step.summary.isEmpty ? null : Text(step.summary),
              trailing: elapsed == null
                  ? null
                  : Text(elapsed,
                      style: TextStyle(
                          color:
                              Theme.of(context).colorScheme.outline)),
            )
          : ExpansionTile(
              leading: Icon(icon, color: color),
              title: Text('$index. ${step.title}'),
              subtitle: Text(step.summary),
              trailing: elapsed == null
                  ? null
                  : Text(elapsed,
                      style: TextStyle(
                          color:
                              Theme.of(context).colorScheme.outline)),
              childrenPadding:
                  const EdgeInsets.fromLTRB(24, 0, 16, 12),
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
