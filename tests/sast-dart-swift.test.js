// Tests for Dart/Flutter and Swift SAST support (sast/src/chunker, sast/src/analyzer catalogs).
//
// Guards the shapes that are easy to get wrong in these two languages:
//   Dart  — multi-line named-parameter signatures, arrow bodies, abstract members,
//           unnamed extensions, generated-file skipping
//   Swift — nested types, inline attributes, `class func`, computed properties,
//           protocol requirements, Allman braces, multi-line strings holding '{'
//
// Run: node --test tests/sast-dart-swift.test.js

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { chunkFile } from '../sast/src/chunker/dispatcher.js';
import { buildChunks } from '../sast/src/chunker/buildChunks.js';
import { stripComments } from '../sast/src/chunker/commentStrippers.js';
import { DEFAULT_VULN_CLASSES, filterVulnClassesForLanguage } from '../sast/src/analyzer/vulnCatalog.js';
import { filterMalwareClassesForLanguage, DEFAULT_MALWARE_CLASSES } from '../sast/src/analyzer/malwareCatalog.js';

function tmpFile(name, content) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'ubel-ds-')));
  const p = path.join(dir, name);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
  return p;
}
const byName = (chunks, name) => chunks.find(c => c.name === name);

const DART = `import 'package:http/http.dart' as http;

const apiKey = 'sk_live_x';

void main() async {
  runApp(const MyApp());
}

class Auth {
  final Map<String, String> cache = {
    'a': 'b',
  };

  Auth(this.base);

  const Auth.named({required this.base});

  String get token => cache['t'] ?? '';

  @override
  bool operator ==(Object other) => other is Auth;

  Future<http.Response> login({
    required String user,
    required String pass,
  }) async {
    final url = 'http://$base/login?u=$user&p=\${pass}'; // trailing comment
    return http.get(Uri.parse(url));
  }

  void abstractish();

  Widget build(BuildContext context) => Scaffold(
        body: Center(child: Text('hi')),
      );

  void after() {
    print('still in class');
  }
}

extension on int {
  int twice() {
    return this * 2;
  }
}
`;

const SWIFT = `import Foundation
@testable import MyApp

protocol Fetcher {
    func fetch(_ url: URL) -> Data
    var name: String { get }
}

@MainActor
final class Login: UIViewController {
    static let shared = Login()
    var cache: [String: String] = [:] {
        didSet { print("changed") }
    }

    struct Inner {
        func inner() -> Int {
            return 1
        }
    }

    var displayName: String {
        return "x"
    }

    @IBAction func tapped(_ sender: Any) {
        let q = "SELECT * FROM u WHERE n = '\\(name)'"
    }

    class func make() -> Login {
        return Login()
    }

    func handler(_ c: Int,
                 didReceive m: Int)
    {
        let s = """
        { not a brace
        """
    }

    func after() { print("still in class") }
}

extension Login: UITextFieldDelegate where Self: UIViewController {
    func textFieldShouldReturn(_ f: UITextField) -> Bool { return true }
}

func topLevel(a: Int) -> Int {
    a + 1
}
`;

test('Dart: chunks members including multi-line named-parameter signatures and arrow bodies', () => {
  const chunks = chunkFile(tmpFile('lib/auth.dart', DART));
  const names = chunks.filter(c => c.type !== 'imports' && c.type !== 'module_code').map(c => `${c.class}.${c.name}`);
  assert.deepEqual(names, [
    'null.main', 'Auth.token', 'Auth.operator ==', 'Auth.login', 'Auth.build', 'Auth.after', 'extension_on_int.twice',
  ]);

  const login = byName(chunks, 'login');
  assert.match(login.code, /required String pass,/);
  assert.match(login.code, /return http\.get/);          // body not lost after the parameter-list braces
  assert.ok(login.code.trimEnd().endsWith('}'));

  const build = byName(chunks, 'build');
  assert.match(build.code, /Center\(child: Text\('hi'\)\)/);   // multi-line arrow body kept whole
  assert.doesNotMatch(build.code, /after/);                  // …and did not run on into the next member
});

test('Dart: bodyless members and fields stay in module_code, not as chunks', () => {
  const chunks = chunkFile(tmpFile('lib/auth.dart', DART));
  const mod = chunks.find(c => c.type === 'module_code');
  assert.match(mod.code, /void abstractish\(\);/);
  assert.match(mod.code, /const Auth\.named/);
  assert.match(mod.code, /apiKey/);
  assert.doesNotMatch(mod.code, /^import /m);               // imports have their own chunk
});

test('Swift: nested types, attributes, computed props, Allman braces, multi-line strings', () => {
  const chunks = chunkFile(tmpFile('Sources/Login.swift', SWIFT));
  const names = chunks.filter(c => c.type !== 'imports' && c.type !== 'module_code').map(c => `${c.class}.${c.name}`);
  assert.deepEqual(names, [
    'Inner.inner', 'Login.displayName', 'Login.tapped', 'Login.make', 'Login.handler', 'Login.after',
    'Login.textFieldShouldReturn', 'null.topLevel',
  ]);
  // `after` is only found if the '{' inside the """ string did not desync depth tracking.
  assert.match(byName(chunks, 'handler').code, /not a brace/);
  // protocol requirements are not chunked as functions
  assert.equal(byName(chunks, 'fetch'), undefined);
});

test('comment stripping: strings containing // and nested block comments survive', () => {
  const swift = stripComments('let u = "https://x.y/z" // gone\n/* a /* nested */ still */ let b = 1 / 2 / 3\nlet r = #"raw // keep"#', 'a.swift');
  assert.match(swift, /https:\/\/x\.y\/z/);
  assert.doesNotMatch(swift, /gone|nested|still/);
  assert.match(swift, /1 \/ 2 \/ 3/);                       // division is not a regex literal
  assert.match(swift, /raw \/\/ keep/);

  const dart = stripComments("var t = '''\nhttp://multi\n''';  // gone\nvar r = r'no\\' // c", 'a.dart');
  assert.match(dart, /http:\/\/multi/);
  assert.doesNotMatch(dart, /gone/);
});

test('walker: picks up .dart/.swift, honours the flutter alias, skips generated Dart', () => {
  const dir = path.dirname(path.dirname(tmpFile('lib/a.dart', DART)));
  fs.writeFileSync(path.join(dir, 'lib', 'model.g.dart'), 'class G { void gen() {} }\n');
  fs.mkdirSync(path.join(dir, 'ios', 'Pods'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'ios', 'Pods', 'Vendored.swift'), 'func v() {}\n');
  fs.writeFileSync(path.join(dir, 'ios', 'App.swift'), SWIFT);

  const files = f => [...new Set(buildChunks({ workingDir: dir, languages: f, log: () => {} }).map(c => path.relative(dir, c.file)))].sort();
  assert.deepEqual(files(['flutter']), ['lib/a.dart']);            // not model.g.dart
  assert.deepEqual(files(['swift']), ['ios/App.swift']);           // not Pods/
});

test('catalog: Dart/Swift get generic + mobile classes but not the server-side web set', () => {
  for (const lang of ['Dart', 'Swift']) {
    const names = filterVulnClassesForLanguage(DEFAULT_VULN_CLASSES, lang).map(c => c.name);
    assert.ok(names.includes('hardcoded secret or credential'));
    assert.ok(names.includes('insecure TLS / certificate validation (mobile)'));
    assert.ok(names.includes('insecure local data storage (mobile)'));
    assert.ok(!names.includes('cross-site request forgery (CSRF)'));
    assert.ok(!names.includes('insecure CORS policy'));
  }
  // mobile classes never leak into other languages
  const kotlin = filterVulnClassesForLanguage(DEFAULT_VULN_CLASSES, 'Kotlin').map(c => c.name);
  assert.ok(!kotlin.some(n => n.endsWith('(mobile)')));
  // Swift-only / Dart-only signals are scoped to the right class lists
  const swiftOnly = DEFAULT_VULN_CLASSES.find(c => c.name === 'unsafe deserialization');
  assert.ok(swiftOnly.languages.includes('swift') && !swiftOnly.languages.includes('dart'));
});

test('malware catalog: every malware class applies to Dart and Swift', () => {
  const all = DEFAULT_MALWARE_CLASSES.length;
  assert.equal(filterMalwareClassesForLanguage(DEFAULT_MALWARE_CLASSES, 'Dart').length, all);
  assert.equal(filterMalwareClassesForLanguage(DEFAULT_MALWARE_CLASSES, 'Swift').length, all);
});
