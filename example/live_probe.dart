// Read-only live probe: proves the Dart LspClient talks to the real stagenet LSP.
// No faucet/open (rate-limited + consumes test SOQ) — just info/health/towers.
import 'package:soqushield_sdk/soqushield_sdk.dart';

Future<void> main() async {
  final ln = SoqLightning(baseUrl: 'https://lsp.soqu.org');
  final info = await ln.info();
  print('info: peer=${info['peer_name']} net=${info['network']} '
      'maxChannelSat=${info['max_channel_sat']} proto=${info['protocol_version']}');
  try {
    final h = await ln.health();
    print('health: $h');
  } catch (e) {
    print('health: $e');
  }
  final t = await ln.towerStatus();
  print('towers: ${t.reachable}/${t.towerCount} reachable, available=${t.available}');
  for (final tw in t.towers) {
    print('  - ${tw.name}: available=${tw.available} '
        'watched=${tw.status?.watchedChannels}');
  }
}
