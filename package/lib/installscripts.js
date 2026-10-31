'use strict';
// installscripts.js — reads the COMMAND LINE of an install-time hook (an npm `postinstall` script, a Composer script, a `Exec` task, a shell
// line in a build file) and says what it does, without running it. Returns signals, not verdicts: the caller decides how serious a signal is
// from where it was found (a `postinstall` that runs `curl | sh` is critical; the same text in a README is not scanned at all).
//
//   download_exec      downloads code and runs it in one go (`curl … | sh`, `iex (iwr …)`, `bash <(curl …)`, `certutil -urlcache`, `mshta http…`)
//   fetch              downloads something (curl, wget, Invoke-WebRequest, Start-BitsTransfer, `git clone`, `npx <pkg>` …)
//   runtime_install    installs further packages at run time (`npm i`, `pip install`, `npx -y pkg`, `gem install`, `go install`, `apt-get install` …)
//   shell_inline       runs a script given inline (`sh -c`, `bash -c`, `node -e`, `python -c`, `powershell -Command`, `eval`)
//   obfuscated_inline  encoded payload on the command line (`powershell -enc`, `base64 -d | sh`, `echo … | base64 -d`, `node -e "eval(atob(…))"`)
//   credential_access  reads credentials or dumps the environment (`~/.ssh`, `.npmrc`, `.aws`, `printenv`, `env |`, `$NPM_TOKEN`)
//   persistence        survives the install (`crontab`, `systemctl enable`, `launchctl load`, `schtasks`, `reg add … Run`, `>> ~/.bashrc`)
//   destructive        deletes or overwrites broadly (`rm -rf /`, `rm -rf ~`, `dd of=/dev/…`, `mkfs`, `format c:`)
//   privilege          escalates or loosens permissions (`sudo`, `chmod 777`, `chmod +s`, `chown root`, `setcap`)
//   native_build       compiles native code (`node-gyp`, `prebuild-install`, `cmake-js`, `make`, `cargo build`, `go build`) — normal for native packages
//   files              local script files the command runs (`node scripts/post.js`, `sh ./x.sh`, `python setup.py`), to be analysed as install-time code
//   urls               URLs written in the command

const URL_RE = /\b(?:https?|ftp|wss?):\/\/[^\s"'`<>)\\]+/gi;

const RULES = [
  ['download_exec', /\b(?:curl|wget|fetch|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|k|c|fi)?sh\b/i, 'pipes a download into a shell'],
  ['download_exec', /\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:python[0-9.]*|node|perl|ruby|php)\b/i, 'pipes a download into an interpreter'],
  ['download_exec', /\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b/i, 'runs a downloaded script through process substitution'],
  ['download_exec', /\b(?:iex|invoke-expression)\b[^\n]*\b(?:iwr|invoke-webrequest|downloadstring|downloadfile|net\.webclient|irm|invoke-restmethod)\b|\b(?:iwr|invoke-webrequest|irm|invoke-restmethod)\b[^\n]*\|\s*(?:iex|invoke-expression)\b/i, 'evaluates downloaded PowerShell'],
  ['download_exec', /\bcertutil(?:\.exe)?\b[^\n]*-urlcache\b|\bbitsadmin\b[^\n]*\/transfer\b|\bmshta(?:\.exe)?\s+https?:|\bregsvr32\b[^\n]*\/i:https?:|\brundll32\b[^\n]*https?:/i, 'uses a Windows download-and-run helper'],
  ['download_exec', /\b(?:curl|wget)\b[^;&\n]*?(?:-o|-O|--output|>)\s*\S+[^;&\n]*?\s*(?:&&|;)\s*(?:chmod\s+(?:\+x|[0-7]*[1357][0-7]*)\s+\S+\s*(?:&&|;)\s*)?(?:\.\/|sh\s|bash\s|python[0-9.]*\s|node\s|\/tmp\/|start\s)/i, 'downloads a file and runs it'],
  ['reverse_shell', /\/dev\/(?:tcp|udp)\/|\b(?:nc|ncat|netcat)\s+(?:-[a-z]*e\b|[^\n]*\s-e\s+\/bin\/(?:ba)?sh)|\bbash\s+-i\s*>&|\bsh\s+-i\s*<&|\bsocat\s+[^\n]*exec:|\bmkfifo\s+[^\n]*\b(?:nc|ncat|netcat)\b/i, 'opens a reverse shell'],
  ['crypto_mining', /stratum\+(?:tcp|ssl)|\b(?:xmrig|cpuminer|minerd|cryptonight|minexmr|nanopool|supportxmr|moneroocean|nicehash)\b|--donate-level/i, 'refers to a cryptocurrency miner'],
  ['fetch', /\b(?:curl|wget|aria2c|iwr|invoke-webrequest|irm|invoke-restmethod|start-bitstransfer|certutil|bitsadmin|git\s+(?:clone|fetch|pull)|svn\s+(?:co|checkout)|hg\s+clone|scp|rsync|ftp|tftp|nc|ncat|netcat)\b/i, 'contacts a remote host'],
  ['fetch', /\bnpx\s+(?:--?[\w-]+\s+)*(?:@?[\w.-]+\/)?[\w.-]+/i, 'fetches and runs a package with npx'],
  ['runtime_install', /\bnpx\s+(?:-y\b|--yes\b|--package\b|-p\b)|\bnpm\s+(?:exec|x)\b/i, 'npx / npm exec downloads and runs a package'],
  ['runtime_install', /\b(?:npm|pnpm|yarn|bun)\s+(?:i|in|ins|install|add|ci|update|up|upgrade|dlx|create)\b/i, 'installs npm packages'],
  ['runtime_install', /\b(?:pip[0-9.]*|pipx|uv(?:\s+pip)?|poetry|pdm|conda|mamba)\s+(?:install|add|run|sync)\b|\bpython[0-9.]*\s+-m\s+(?:pip|ensurepip|easy_install)\b|\beasy_install\b|\bpip[0-9.]*\s+download\b/i, 'installs Python packages'],
  ['runtime_install', /\bgem\s+install\b|\bbundle\s+(?:install|add|update)\b/i, 'installs Ruby gems'],
  ['runtime_install', /\bcargo\s+(?:install|add|update)\b/i, 'installs Rust crates'],
  ['runtime_install', /\bgo\s+(?:get|install|mod\s+download)\b/i, 'installs Go modules'],
  ['runtime_install', /\bdotnet\s+(?:add\s+package|tool\s+install|restore|nuget\s+push)\b|\bnuget(?:\.exe)?\s+install\b|\bInstall-Package\b/i, 'installs .NET packages'],
  ['runtime_install', /\bcomposer\s+(?:require|install|update|global)\b/i, 'installs Composer packages'],
  ['runtime_install', /\b(?:dart|flutter)\s+pub\s+(?:add|get|global\s+activate)\b|\bpub\s+get\b/i, 'installs Dart packages'],
  ['runtime_install', /\b(?:apt(?:-get)?|yum|dnf|zypper|apk|pacman|brew|choco|scoop|winget|snap|port)\s+(?:-[\w-]+\s+)*(?:install|add|-S)\b/i, 'installs operating-system packages'],
  ['runtime_install', /\bdocker\s+(?:pull|run|build)\b|\bpodman\s+(?:pull|run)\b/i, 'pulls a container image'],
  ['shell_inline', /\b(?:ba|z|da|k)?sh\s+-[a-z]*c\s|\bcmd(?:\.exe)?\s+\/[ck]\b|\bpowershell(?:\.exe)?\b[^\n]*-(?:c|command)\b|\bpwsh\b[^\n]*-(?:c|command)\b|\bnode\s+(?:-e|--eval|-p)\b|\bpython[0-9.]*\s+-c\b|\bperl\s+-e\b|\bruby\s+-e\b|\bphp\s+-r\b|(?:^|[;&|]\s*)eval\s/i, 'runs an inline script'],
  ['obfuscated_inline', /\bpowershell(?:\.exe)?\b[^\n]*\s-(?:e|enc|encodedcommand)\b|\bbase64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:ba|z)?sh\b|\b(?:echo|printf)\b[^\n]*\|\s*base64\s+(?:-d|--decode|-D)\b|\batob\(|Buffer\.from\([^)]*['"`]base64['"`]\)|\bfromCharCode\b|\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}|\bxxd\s+-r\b[^\n]*\|\s*(?:ba|z)?sh\b/i, 'contains an encoded payload'],
  ['credential_access', /(?:~|\$HOME|%USERPROFILE%|\$\{HOME\}|\/root|\/home\/[\w.-]+|C:\\Users\\[\w.-]+)[\\/]+(?:\.ssh|\.aws|\.azure|\.config[\\/]gcloud|\.gnupg|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.docker[\\/]config\.json|\.kube[\\/]config|\.bash_history|\.zsh_history|\.gem[\\/]credentials|\.cargo[\\/]credentials|\.nuget|\.composer[\\/]auth\.json)|\b(?:printenv|env\s*\||export\s+-p|set\s*\|)\b|\$(?:\{)?(?:NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|PYPI_TOKEN|TWINE_PASSWORD|CARGO_REGISTRY_TOKEN|GITLAB_TOKEN|AZURE_CLIENT_SECRET|SSH_AUTH_SOCK|DOCKER_PASSWORD)\b|\bgit\s+config\s+--get\b[^\n]*(?:user|credential)|\bsecurity\s+find-(?:generic|internet)-password\b|\bcmdkey\s+\/list\b|\bvaultcmd\b/i, 'reads credentials or environment secrets'],
  ['persistence', /\bcrontab\b|\/etc\/cron|\bsystemctl\s+(?:--user\s+)?(?:enable|daemon-reload)\b|\/etc\/systemd|\.config\/systemd|\blaunchctl\s+(?:load|bootstrap|submit)\b|LaunchAgents|LaunchDaemons|\bschtasks(?:\.exe)?\s+\/create\b|\breg(?:\.exe)?\s+add\b[^\n]*\\(?:Run|RunOnce)\b|CurrentVersion\\Run|\bStartup\\|>>?\s*~?\/?(?:\.bashrc|\.bash_profile|\.zshrc|\.profile|\.zprofile|\/etc\/profile|\/etc\/rc\.local)|\bnew-service\b|\bsc(?:\.exe)?\s+create\b|\bat\s+now\b|authorized_keys|\bupdate-rc\.d\b|\binsserv\b/i, 'sets up something that survives the install'],
  ['destructive', /\brm\s+(?:-[a-z]*[rf][a-z]*\s+)+(?:--no-preserve-root\s+)?(?:\/|~|\$HOME|\$\{HOME\}|\*|\.\s|\/\*)(?:\s|$)|\bdd\s+[^\n]*\bof=\/dev\/|\bmkfs(?:\.\w+)?\b|\bformat\s+[a-z]:|\bdel\s+\/[sfq]\b[^\n]*[a-z]:\\|\bRemove-Item\b[^\n]*-Recurse[^\n]*-Force[^\n]*(?:[A-Za-z]:\\|\$HOME|~)|:\(\)\s*\{\s*:\|:&\s*\};:|\bshred\b|\bwipefs\b|\bcipher\s+\/w:/i, 'deletes or overwrites broadly'],
  ['privilege', /\bsudo\b|\bdoas\b|\bchmod\s+(?:-R\s+)?(?:[0-7]?777|[ugoa]*\+[rwx]*s|[24][0-7]{3})\b|\bchown\s+(?:-R\s+)?root\b|\bsetcap\b|\bsetuid\b|\brunas\b|\bStart-Process\b[^\n]*-Verb\s+RunAs\b|\bpkexec\b/i, 'changes privileges or permissions'],
  ['native_build', /\bnode-gyp\b|\bprebuild(?:ify|-install)?\b|\bnode-pre-gyp\b|\bcmake-js\b|\bnode-gyp-build\b|\bcmake\b|\bmake\b|\bcc\b|\bgcc\b|\bg\+\+\b|\bclang\b|\bcargo\s+build\b|\bgo\s+build\b|\bmsbuild\b|\bdotnet\s+build\b|\bpython[0-9.]*\s+setup\.py\s+build/i, 'builds native code'],
];

const FILE_RUNNERS = [
  /\b(?:node(?:js)?|nodemon|tsx|ts-node|bun(?:\s+run)?|deno\s+run(?:\s+-[\w-]+)*)\s+(?:--?[\w-]+(?:=\S+)?\s+)*(?:\.\/)?([\w@./\\~-]+\.(?:[cm]?[jt]s|json|node))\b/gi,
  /\b(?:ba|z|da|k)?sh\s+(?:-[a-z]+\s+)*(?:\.\/)?([\w@./\\~-]+)/gi,
  /\bpython[0-9.]*\s+(?:-[\w]+\s+)*(?:\.\/)?([\w@./\\~-]+\.py)\b/gi,
  /\b(?:perl|ruby|php|lua|Rscript)\s+(?:-[\w]+\s+)*(?:\.\/)?([\w@./\\~-]+\.(?:pl|rb|php|lua|R))\b/gi,
  /\b(?:pwsh|powershell(?:\.exe)?)\b[^\n]*?-(?:file|f)\s+["']?(?:\.\/|\.\\)?([\w@./\\~ -]+\.ps1)/gi,
  /\b(?:cmd(?:\.exe)?\s+\/[ck]\s+)?(?:\.\\|\.\/)?([\w@./\\~-]+\.(?:bat|cmd))\b/gi,
  /(?:^|[;&|(]\s*)\.\/([\w@./~-]+)/g,
];

const SPLIT = /\s*(?:&&|\|\||;|\n)\s*/;

/** @returns {{signals:Map<string,{detail:string, commands:string[]}>, files:string[], urls:string[], commands:string[]}} */
export function analyzeCommand(command) {
  const cmd = String(command ?? '');
  const signals = new Map();
  const note = (id, detail, c) => {
    const e = signals.get(id) || signals.set(id, { detail, commands: [] }).get(id);
    const short = c.length > 240 ? `${c.slice(0, 237)}…` : c;
    if (!e.commands.includes(short) && e.commands.length < 6) e.commands.push(short);
  };
  // whole-line rules first (pipes cross `&&` / `;` boundaries only inside one pipeline), then per-clause
  for (const [id, re, detail] of RULES) if (re.test(cmd)) note(id, detail, cmd.trim());
  const files = new Set();
  for (const clause of cmd.split(SPLIT)) {
    const c = clause.trim();
    if (!c) continue;
    for (const re of FILE_RUNNERS) {
      re.lastIndex = 0;
      for (let m; (m = re.exec(c));) {
        const f = m[1].replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '');
        if (f && !f.startsWith('..') && !/^(?:-|\$|%)/.test(f) && !/^(?:echo|exit|true|false|node_modules\/\.bin)/.test(f)) files.add(f);
      }
    }
  }
  const urls = [...new Set([...cmd.matchAll(URL_RE)].map(m => m[0].replace(/[.,;]+$/, '')))].slice(0, 20);
  return { signals, files: [...files].slice(0, 20), urls, commands: cmd.split(SPLIT).map(s => s.trim()).filter(Boolean).slice(0, 30) };
}

/** npm lifecycle scripts: which run for a CONSUMER that installs the package from the registry. */
export const NPM_CONSUMER_HOOKS = ['preinstall', 'install', 'postinstall'];
export const NPM_OTHER_HOOKS = ['prepare', 'prepublish', 'prepublishOnly', 'prepack', 'postpack', 'preuninstall', 'uninstall', 'postuninstall', 'dependencies'];
