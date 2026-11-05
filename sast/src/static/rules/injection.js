'use strict';

import { isCleared } from '../taint.js';
import { call, assign, custom, WEB, JVM, ALLL } from './helpers.js';

const m = (names) => new RegExp(String.raw`(?:^|[.:])(?:${names})$`);      // method name at the end of the callee
const x = (names) => new RegExp(String.raw`^(?:${names})$`);                // whole callee
const notDot = (c) => !c.viaDot;
const kw = (c, name) => new RegExp(String.raw`\b${name}\s*[=:]\s*(?:True|true)\b`).test(c.text);

// ═══ SQL injection ═══════════════════════════════════════════════════════════
const SQL = { cls: 'SQL injection', group: 'sql', sqlGate: true, sev: 'high', fix: 'Use parameterised queries / prepared statements (bind values as parameters) instead of building the SQL string from input; validate identifiers against an allowlist.' };
const sqlWhat = 'executes a SQL statement built from a non-constant string';

const SQL_RULES = [
  call({ ...SQL, id: 'sqli-python', langs: ['python'], what: sqlWhat, args: [0],
    callee: m('execute|executemany|executescript|mogrify|exec_driver_sql|raw|extra|read_sql|read_sql_query|read_sql_table|from_statement|execute_sql') }),
  call({ ...SQL, id: 'sqli-python-text', langs: ['python'], what: sqlWhat, args: [0], callee: x('text|sqlalchemy\\.text|sa\\.text') }),
  call({ ...SQL, id: 'sqli-js', langs: ['js'], what: sqlWhat, args: [0],
    callee: m('query|queryRaw|executeRaw|\\$queryRawUnsafe|\\$executeRawUnsafe|queryRawUnsafe|executeRawUnsafe|raw|whereRaw|havingRaw|orderByRaw|groupByRaw|joinRaw|selectRaw|literal|unsafe') }),
  call({ ...SQL, id: 'sqli-js-db', langs: ['js'], what: sqlWhat, args: [0],
    callee: /(?:^|\.)(?:db|database|sqlite\w*|conn\w*|pool|client|knex|sequelize|trx|tx|dbh|mysql\w*|pg\w*)\.(?:get|all|run|each|exec|prepare|execute)$/ }),
  call({ ...SQL, id: 'sqli-php', langs: ['php'], what: sqlWhat,
    callee: m('query|exec|prepare|mysqli_query|mysql_query|pg_query|pg_exec|sqlite_query|sqlite_exec|mssql_query|real_query|multi_query|unprepared|whereRaw|selectRaw|havingRaw|orderByRaw|groupByRaw|get_results|get_row|get_var|get_col|execute_query'),
    argsFn: (c) => /^(?:mysqli_|pg_|sqlsrv_)/.test(c.callee) || /^mysqli_query$/.test(c.callee) ? [1] : [0] }),
  call({ ...SQL, id: 'sqli-php-db', langs: ['php'], what: sqlWhat, args: [0], callee: x('DB::(?:select|insert|update|delete|statement|unprepared|raw|selectOne)') }),
  call({ ...SQL, id: 'sqli-ruby', langs: ['ruby'], what: sqlWhat, args: [0],
    callee: m('execute|exec_query|exec_update|exec_delete|exec_insert|select_all|select_one|select_rows|select_value|select_values|find_by_sql|count_by_sql|where|having|order|group|joins|pluck|from|reorder|update_all|delete_all|lock|calculate'),
    argUnless: /^\s*(?:\{|:?\w+\s*:|:\w+\s*=>|\[\s*["'`]|\w+\s*=>)/ }),
  call({ ...SQL, id: 'sqli-go', langs: ['go'], what: sqlWhat,
    callee: m('Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Prepare|PrepareContext|Raw|Select|Get|NamedQuery|MustExec|Queryx|QueryRowx|Where|Having|Order|Group|Joins|NamedExec|SelectContext|GetContext'),
    argsFn: (c) => /Context$/.test(c.name) ? [1] : /^(?:Select|Get|NamedQuery|NamedExec)$/.test(c.name) ? [1] : [0],
    when: (c, f) => !/^(?:\w+\.)*(?:Header|Form|Values|Query\(\)|URL)\.Get$/.test(c.callee) && !/^(?:r|req|request)\.URL\.Query\(\)\.Get$/.test(c.chain) }),
  call({ ...SQL, id: 'sqli-rust', langs: ['rust'], what: sqlWhat, args: [0],
    callee: x('(?:sqlx::)?query|(?:sqlx::)?query_as|(?:sqlx::)?query_scalar|diesel::sql_query|sql_query|[\\w.]+\\.(?:execute|execute_batch|prepare|batch_execute|simple_query|query_one|query_opt|query_row|query_map|prepare_cached|raw_sql)|[\\w.]+\\.query') }),
  call({ ...SQL, id: 'sqli-jvm', langs: JVM, what: sqlWhat, args: [0],
    callee: m('executeQuery|executeUpdate|execute|executeLargeUpdate|addBatch|prepareStatement|prepareCall|createQuery|createNativeQuery|createSQLQuery|query|queryForObject|queryForList|queryForMap|queryForRowSet|queryForInt|queryForLong|update|batchUpdate|rawQuery|execSQL|nativeQuery|SimpleSQLiteQuery|execAndMap') }),
  call({ ...SQL, id: 'sqli-csharp', langs: ['csharp'], what: sqlWhat, args: [0],
    callee: m('ExecuteReader|ExecuteNonQuery|ExecuteScalar|ExecuteSqlRaw|ExecuteSqlCommand|FromSqlRaw|SqlQuery|SqlQueryRaw|Query|QueryFirst|QueryFirstOrDefault|QuerySingle|QuerySingleOrDefault|Execute|ExecuteAsync|QueryAsync|ExecuteScalarAsync|ExecuteReaderAsync|ExecuteNonQueryAsync|ExecuteSqlRawAsync|SqlCommand|OleDbCommand|NpgsqlCommand|MySqlCommand|SqliteCommand|OracleCommand|SqlDataAdapter|OdbcCommand') }),
  call({ ...SQL, id: 'sqli-swift', langs: ['swift'], what: sqlWhat,
    callee: m('sqlite3_exec|sqlite3_prepare|sqlite3_prepare_v2|sqlite3_prepare_v3|executeQuery|executeUpdate|execute|prepare|Statement|query|run|fetchAll|fetchOne|fetchCursor|fetchSet|rawQuery|SQLRequest'),
    argsFn: (c) => /^sqlite3_/.test(c.name) ? [1] : [0] }),
  call({ ...SQL, id: 'sqli-dart', langs: ['dart'], what: sqlWhat, args: [0],
    callee: m('rawQuery|rawInsert|rawUpdate|rawDelete|execute|customStatement|customSelect|customUpdate|execSQL|runCustom|query') }),
  call({ ...SQL, id: 'sqli-c', langs: ['c'], what: sqlWhat,
    callee: x('mysql_query|mysql_real_query|sqlite3_exec|PQexec|SQLExecDirect|OCIStmtPrepare|sqlite3_prepare|sqlite3_prepare_v2|sqlite3_prepare_v3|mysql_stmt_prepare|PQprepare|SQLPrepare|PQexecParams'),
    argsFn: (c) => /^(?:sqlite3_|PQ|mysql_real_query|mysql_stmt_prepare)/.test(c.callee) ? [1] : [0] }),
];

// ═══ Command injection ═══════════════════════════════════════════════════════
const CMD = { cls: 'command injection', group: 'shell', sev: 'critical', fix: 'Do not build shell command lines from input. Call the program directly with an argument array (no shell), validate the value against an allowlist, and never pass user data to a shell interpreter.' };
const cmdWhat = 'runs an operating-system command built from this value';
const SHELLNAMES = /^["'`]?(?:\/bin\/)?(?:sh|bash|zsh|ash|dash|ksh|csh|cmd|cmd\.exe|powershell|pwsh|powershell\.exe)["'`]?$/;

const CMD_RULES = [
  call({ ...CMD, id: 'cmdi-python-os', langs: ['python'], what: cmdWhat, args: [0],
    callee: x('os\\.(?:system|popen|popen2|popen3|popen4|startfile)|commands\\.getoutput|commands\\.getstatusoutput|subprocess\\.(?:getoutput|getstatusoutput)|pty\\.spawn|asyncio\\.create_subprocess_shell|os\\.exec\\w+|os\\.spawn\\w+') }),
  call({ ...CMD, id: 'cmdi-python-subprocess', langs: ['python'], what: 'runs a command through the shell (shell=True) built from this value', args: [0],
    callee: x('subprocess\\.(?:call|run|Popen|check_output|check_call)|Popen|check_output|check_call'), when: (c) => kw(c, 'shell') }),
  call({ ...CMD, id: 'cmdi-js', langs: ['js'], what: cmdWhat, args: [0],
    callee: x('(?:exec|execSync|execa\\.command|execaCommand|execaCommandSync|shelljs\\.exec|shell\\.exec|sh\\.exec|spawnSync|spawn|execFile|execFileSync|fork|(?:child_process|cp|childProcess|proc|require)\\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork))'),
    when: (c) => !c.viaDot || /\./.test(c.callee), }),
  call({ ...CMD, id: 'cmdi-php', langs: ['php'], what: cmdWhat, args: [0], callee: x('system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|expect_popen') }),
  call({ ...CMD, id: 'cmdi-ruby', langs: ['ruby'], what: cmdWhat, args: [0],
    callee: x('system|exec|spawn|popen|popen3|capture2|capture2e|capture3|sh|(?:Open3|IO|Kernel|PTY)\\.\\w+|open') }),
  call({ ...CMD, id: 'cmdi-go', langs: ['go'], what: cmdWhat, callee: x('exec\\.Command|exec\\.CommandContext'),
    argsFn: (c) => { const o = c.name === 'CommandContext' ? 1 : 0; const prog = (c.args[o]?.lit || ''); return SHELLNAMES.test(prog.trim()) ? c.args.map((_, i) => i).filter(i => i > o) : [o]; } }),
  call({ ...CMD, id: 'cmdi-rust', langs: ['rust'], what: cmdWhat, args: [0], callee: x('(?:std::process::)?Command::new|tokio::process::Command::new') }),
  call({ ...CMD, id: 'cmdi-jvm-runtime', langs: JVM, what: cmdWhat, args: [0], chain: true, callee: /(?:^|\.)Runtime\.getRuntime\(\)\.exec$|^(?:rt|runtime)\.exec$/ }),
  call({ ...CMD, id: 'cmdi-jvm-pb', langs: JVM, what: cmdWhat, callee: x('ProcessBuilder|(?:\\w+\\.)?command'),
    argsFn: (c) => (c.args.some(a => /^["']?(?:-c|\/c|-Command)["']?$/.test(a.lit.trim())) || c.args.some(a => SHELLNAMES.test(a.lit.trim()))) ? c.args.map((_, i) => i) : [0],
    when: (c) => c.isNew || /\.command$/.test(c.callee) }),
  call({ ...CMD, id: 'cmdi-csharp', langs: ['csharp'], what: cmdWhat, callee: x('(?:System\\.Diagnostics\\.)?Process\\.Start|ProcessStartInfo'), args: 'any' }),
  call({ ...CMD, id: 'cmdi-c', langs: ['c'], what: cmdWhat, callee: x('system|popen|_popen|_wsystem|execl|execlp|execle|execv|execvp|execve|execvpe|WinExec|ShellExecute\\w*|CreateProcess\\w*|wordexp|posix_spawn|posix_spawnp'), args: 'any' }),
  call({ ...CMD, id: 'cmdi-dart', langs: ['dart'], what: cmdWhat, callee: x('Process\\.(?:run|runSync|start)|Shell\\(\\)\\.run'),
    argsFn: (c) => (/runInShell\s*:\s*true/.test(c.text) ? c.args.map((_, i) => i) : [0]) }),
  call({ ...CMD, id: 'cmdi-swift', langs: ['swift'], what: cmdWhat, args: 'any', callee: x('system|popen|posix_spawn|NSTask|Process\\.launchedProcess') }),
  assign({ ...CMD, id: 'cmdi-assign-psi', langs: ['csharp'], what: cmdWhat, lhs: /\.(?:FileName|Arguments)$|^(?:FileName|Arguments)$/ }),
  assign({ ...CMD, id: 'cmdi-assign-swift', langs: ['swift'], what: cmdWhat, lhs: /\.(?:launchPath|executableURL|arguments)$/ }),
  // Rust: Command::new("sh").arg("-c").arg(tainted)
  custom({ ...CMD, id: 'cmdi-rust-shell', langs: ['rust'],
    run(flow, emit) {
      for (const ll of flow.ctx.logical) {
        if (!/Command::new\(\s*\)?/.test(ll.text) || !/Command\s*::\s*new\s*\(\s*["'](?:\/bin\/)?(?:sh|bash|cmd|cmd\.exe|powershell)["']/.test(ll.lit)) continue;
        for (const c of flow.ctx.calls) {
          if (c.start < ll.start || c.start >= ll.end || !/(?:^|\.)args?$/.test(c.callee)) continue;
          const st = c.args.flatMap(a => flow.stateOfArg(a, c.line)).filter(s => !isCleared(s, 'shell'));
          if (st.length) { emit(c.start, { desc: `Attacker-controlled input (${st[0].origin || 'parameter ' + st[0].param}) is passed to a shell (sh -c) command line.`, flow: st[0] }); break; }
        }
      }
    } }),
  // Backtick / %x execution with interpolation (PHP, Ruby)
  custom({ ...CMD, id: 'cmdi-backtick', langs: ['php', 'ruby'],
    run(flow, emit) {
      const re = /`([^`\n]*)`/g; let mm;
      while ((mm = re.exec(flow.ctx.literal)) !== null) {
        const innerCode = flow.ctx.code.slice(mm.index + 1, mm.index + 1 + mm[1].length);
        const st = flow.state(innerCode, mm[1]).filter(s => !isCleared(s, 'shell'));
        if (st.length) emit(mm.index, { flowInfo: st[0].kind === 'src' ? { kind: 'src', origin: st[0].origin } : { kind: 'param', params: st }, desc: `Backtick shell execution interpolates ${st[0].origin || 'parameter "' + st[0].param + '"'}.` });
      }
    } }),
];

// ═══ Path traversal ══════════════════════════════════════════════════════════
const PATH = { cls: 'path traversal', group: 'path', sev: 'high', fix: 'Do not use input as a path. Map it to an allowlisted identifier, or resolve the final path (realpath/Path.resolve) and verify it stays under the intended base directory; strip directory components with basename.' };
const pathWhat = 'uses it as a filesystem path';

const PATH_RULES = [
  call({ ...PATH, id: 'path-python', langs: ['python'], what: pathWhat, args: [0],
    callee: x('open|io\\.open|codecs\\.open|os\\.open|os\\.remove|os\\.unlink|os\\.rename|os\\.replace|os\\.rmdir|os\\.removedirs|os\\.mkdir|os\\.makedirs|os\\.listdir|os\\.scandir|os\\.walk|os\\.chmod|os\\.chown|os\\.readlink|os\\.stat|os\\.truncate|shutil\\.(?:copy|copy2|copyfile|copytree|move|rmtree|make_archive|unpack_archive)|send_file|FileResponse|fileinput\\.input|zipfile\\.ZipFile|tarfile\\.open|PIL\\.Image\\.open|Image\\.open|pd\\.read_csv|pandas\\.read_csv|np\\.load|numpy\\.load|[\\w.]+\\.(?:read_text|read_bytes|write_text|write_bytes|open|unlink|rmdir|mkdir|touch)') }),
  call({ ...PATH, id: 'path-js', langs: ['js'], what: pathWhat, args: [0],
    callee: x('(?:fs|fsp|fs\\.promises|fse|fsExtra|fs-extra|promises)\\.(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|readdir|readdirSync|stat|statSync|lstat|access|accessSync|open|openSync|copyFile|copyFileSync|rename|renameSync|mkdir|mkdirSync|readlink|truncate|chmod|opendir|cp|cpSync|remove|ensureFile|outputFile|readJson|writeJson|move|copy)|res\\.(?:sendFile|download|sendfile)|(?:\\w+\\.)?sendFile|reply\\.sendFile|ctx\\.sendFile|require|readFile|readFileSync|createReadStream|createWriteStream|unlink|rimraf|del|sharp|jimp\\.read|Jimp\\.read|pdf\\.read') }),
  call({ ...PATH, id: 'path-js-res', langs: ['js'], what: pathWhat, args: [0], chain: true, callee: /^(?:res|response|reply)(?:\.\w+\(\))*\.(?:sendFile|download|sendfile)$/ }),
  call({ ...PATH, id: 'path-php', langs: ['php'], what: pathWhat, args: [0],
    callee: x('fopen|file_get_contents|file_put_contents|readfile|file|unlink|rmdir|mkdir|rename|copy|touch|chmod|move_uploaded_file|fpassthru|readlink|opendir|scandir|glob|is_file|file_exists|is_dir|filesize|filemtime|parse_ini_file|highlight_file|show_source|imagecreatefrom\\w+|SplFileObject|zip_open|rmdirr|unlink_recursive|Storage::(?:get|put|delete|download|path|disk)|response\\(\\)\\.download|response\\(\\)\\.file'),
    argsFn: (c) => c.name === 'move_uploaded_file' || c.name === 'copy' || c.name === 'rename' ? [1] : [0] }),
  call({ ...PATH, id: 'path-ruby', langs: ['ruby'], what: pathWhat, args: [0],
    callee: x('File\\.(?:read|open|new|write|delete|unlink|readlines|foreach|binread|binwrite|rename|chmod|join|expand_path|exist\\?|file\\?|size|stat|copy|symlink)|IO\\.(?:read|readlines|foreach|binread|write)|FileUtils\\.\\w+|Dir\\.(?:glob|entries|children|foreach|mkdir|rmdir|\\[\\])|send_file|send_data|render|File\\.open|Pathname(?:\\.new)?|Tempfile\\.new|open|read'),
    when: (c) => !(c.callee === 'render' && !/\b(?:file|template)\s*:/.test(c.text)) && !(c.callee === 'File.join' || c.callee === 'File.expand_path') }),
  call({ ...PATH, id: 'path-go', langs: ['go'], what: pathWhat, args: [0],
    callee: x('os\\.(?:Open|OpenFile|Create|ReadFile|WriteFile|Remove|RemoveAll|Mkdir|MkdirAll|Rename|Stat|Lstat|ReadDir|Chmod|Truncate|Readlink|Symlink|Link)|ioutil\\.(?:ReadFile|WriteFile|ReadDir)|http\\.(?:ServeFile|Dir)|filepath\\.(?:Walk|WalkDir|Glob)|(?:c|ctx|e)\\.(?:File|Attachment|SendFile|SaveUploadedFile|Download|FileAttachment)|os\\.DirFS|zip\\.OpenReader|[\\w.]+\\.(?:SaveUploadedFile|FileAttachment)'),
    argsFn: (c) => c.name === 'ServeFile' ? [2] : c.name === 'SaveUploadedFile' ? [1] : c.name === 'Rename' ? [0, 1] : [0] }),
  call({ ...PATH, id: 'path-rust', langs: ['rust'], what: pathWhat, args: [0],
    callee: x('(?:std::)?fs::(?:read|read_to_string|write|remove_file|remove_dir|remove_dir_all|create_dir|create_dir_all|copy|rename|metadata|read_dir|canonicalize|read_link|hard_link|set_permissions)|(?:std::fs::)?File::(?:open|create|options)|OpenOptions::new\\(\\)\\.open|tokio::fs::\\w+|NamedFile::open|NamedFile::open_async|fs::File::open|std::fs::File::open|Path::new|PathBuf::from') }),
  call({ ...PATH, id: 'path-jvm', langs: JVM, what: pathWhat, args: [0],
    callee: x('File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter|Scanner|Paths\\.get|Path\\.of|Files\\.(?:readAllBytes|readAllLines|readString|write|writeString|newInputStream|newOutputStream|newBufferedReader|newBufferedWriter|delete|deleteIfExists|copy|move|list|walk|lines|exists|createFile|createDirectories|createTempFile|size|isDirectory|isRegularFile|probeContentType)|getResourceAsStream|getResource|(?:\\w+\\.)?(?:getRealPath|transferTo)|FileUtils\\.\\w+|ClassPathResource|FileSystemResource|UrlResource|(?:\\w+\\.)?(?:sendFile|download)'),
    when: (c) => !c.isNew || /^(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter|Scanner|ClassPathResource|FileSystemResource)$/.test(c.callee),
    argsFn: (c) => c.name === 'File' && c.args.length === 2 ? [1] : c.name === 'get' || c.name === 'of' ? c.args.map((_, i) => i) : [0] }),
  call({ ...PATH, id: 'path-csharp', langs: ['csharp'], what: pathWhat, args: [0],
    callee: x('(?:System\\.IO\\.)?(?:File\\.(?:ReadAllText|ReadAllBytes|ReadAllLines|ReadLines|WriteAllText|WriteAllBytes|WriteAllLines|AppendAllText|Open|OpenRead|OpenWrite|OpenText|Create|Delete|Copy|Move|Exists|Replace|SetAttributes|GetAttributes|ReadAllTextAsync|WriteAllTextAsync|ReadAllBytesAsync)|Directory\\.(?:GetFiles|GetDirectories|EnumerateFiles|Delete|CreateDirectory|Exists|Move|EnumerateDirectories)|FileStream|StreamReader|StreamWriter|FileInfo|DirectoryInfo|Path\\.GetFullPath|PhysicalFile|File|SendFileAsync|Server\\.MapPath|MapPath)|(?:\\w+\\.)?(?:PhysicalFile|SaveAs|SendFile|TransmitFile|WriteFile)|Path\\.Combine'),
    when: (c) => c.callee !== 'Path.Combine' && c.callee !== 'Path.GetFullPath' }),
  call({ ...PATH, id: 'path-dart', langs: ['dart'], what: pathWhat, args: [0],
    callee: x('File|Directory|Link|(?:File|Directory)\\.fromUri|[\\w.]+\\.(?:readAsString|readAsBytes|readAsLines|writeAsString|writeAsBytes|openRead|openWrite|delete|rename|copy|create|list|exists)|rootBundle\\.load(?:String)?|createStaticHandler|File\\.new'),
    when: (c) => !(c.viaDot && /^[\w.]+\.(?:readAsString|readAsBytes|openRead|exists|delete)$/.test(c.callee) === false) }),
  call({ ...PATH, id: 'path-swift', langs: ['swift'], what: pathWhat, args: [0],
    callee: x('FileManager\\.default\\.(?:contents|createFile|removeItem|copyItem|moveItem|contentsOfDirectory|fileExists|createDirectory|attributesOfItem|destinationOfSymbolicLink|subpathsOfDirectory)|String|Data|NSData|NSString|FileHandle|InputStream|OutputStream|URL|NSURL|fopen|open'),
    when: (c) => /\b(?:contentsOfFile|contentsOf|forReadingAtPath|forWritingAtPath|forUpdatingAtPath|fileURLWithPath|atPath|path|filePath)\b/.test(c.text) || /^FileManager/.test(c.callee) || c.callee === 'fopen' || c.callee === 'open' }),
  call({ ...PATH, id: 'path-c', langs: ['c'], what: pathWhat, callee: x('fopen|freopen|open|openat|creat|remove|unlink|rename|mkdir|rmdir|chmod|chown|stat|lstat|access|opendir|readlink|symlink|link|truncate|tmpfile|_wfopen|CreateFile\\w*|DeleteFile\\w*|realpath|chdir|chroot|ifstream|ofstream|fstream|std::ifstream|std::ofstream|std::fstream|std::filesystem::path'),
    argsFn: (c) => c.name === 'openat' ? [1] : c.name === 'rename' || c.name === 'link' || c.name === 'symlink' ? [0, 1] : [0] }),
];

// ═══ Unsafe deserialization ══════════════════════════════════════════════════
const DESER = { cls: 'unsafe deserialization', group: 'deser', sev: 'critical', fix: 'Never deserialize untrusted data with a format that can instantiate arbitrary types. Use a data-only format (JSON) with a fixed schema, a safe loader (yaml.safe_load), or an explicit type allowlist.' };
const deserWhat = 'deserializes it with a format that can instantiate arbitrary objects';

const DESER_RULES = [
  call({ ...DESER, id: 'deser-python', langs: ['python'], what: deserWhat, args: [0],
    callee: x('(?:pickle|cPickle|_pickle|dill|cloudpickle|shelve|marshal|jsonpickle)\\.(?:loads?|Unpickler|open|decode)|pandas\\.read_pickle|pd\\.read_pickle|joblib\\.load|yaml\\.(?:unsafe_load|unsafe_load_all|full_load|full_load_all)|jsonpickle\\.decode|pickle\\.Unpickler') }),
  call({ ...DESER, id: 'deser-python-yaml', langs: ['python'], what: 'loads YAML with a loader that can construct arbitrary Python objects', args: [0], callee: x('yaml\\.(?:load|load_all)'),
    when: (c) => !/Loader\s*=\s*(?:yaml\.)?(?:C?SafeLoader|BaseLoader)|\bSafeLoader\b|\bCSafeLoader\b|\bBaseLoader\b/.test(c.text) }),
  call({ ...DESER, id: 'deser-python-torch', langs: ['python'], what: 'unpickles a model file (torch.load without weights_only=True)', args: [0], callee: x('torch\\.load'), when: (c) => !/weights_only\s*=\s*True/.test(c.text) }),
  call({ ...DESER, id: 'deser-python-numpy', langs: ['python'], what: 'loads a pickled array (allow_pickle=True)', args: [0], callee: x('(?:np|numpy)\\.load'), when: (c) => /allow_pickle\s*=\s*True/.test(c.text) }),
  call({ ...DESER, id: 'deser-js', langs: ['js'], what: deserWhat, args: [0], callee: x('(?:serialize\\.|nodeSerialize\\.)?unserialize|funcster\\.deepDeserialize|cryo\\.parse|(?:\\w+\\.)?deserialize(?:Function)?') , when: (c) => /unserialize|funcster|cryo/.test(c.callee) }),
  call({ ...DESER, id: 'deser-js-yaml', langs: ['js'], what: 'loads YAML that can construct arbitrary objects (js-yaml < 4 load)', args: [0], conf: 'low', callee: x('(?:yaml|jsyaml|YAML)\\.(?:load|loadAll)'), when: (c, f) => !/\bsafeLoad|safe_load|schema\s*:\s*(?:yaml\.)?(?:JSON|FAILSAFE|CORE)_SCHEMA|DEFAULT_SAFE_SCHEMA/.test(f.ctx.literal) }),
  call({ ...DESER, id: 'deser-php', langs: ['php'], what: deserWhat, args: [0], callee: x('unserialize|igbinary_unserialize|msgpack_unserialize|yaml_parse|yaml_parse_file'), unless: /allowed_classes\s*['"]?\s*=>\s*(?:false|\[\s*\])/ }),
  call({ ...DESER, id: 'deser-ruby', langs: ['ruby'], what: deserWhat, args: [0], callee: x('Marshal\\.(?:load|restore)|(?:YAML|Psych)\\.(?:load|unsafe_load|load_stream|load_file|unsafe_load_file)|Oj\\.(?:load|object_load)|CSV\\.load|Ox\\.load'),
    when: (c) => !/permitted_classes|safe\s*[:=]|mode\s*:\s*:strict|safe_load/.test(c.text) || /unsafe/.test(c.callee) }),
  call({ ...DESER, id: 'deser-jvm-ois', langs: JVM, what: deserWhat, args: [0], callee: x('ObjectInputStream|XMLDecoder|HessianInput|Hessian2Input|BurlapInput|(?:\\w+\\.)?(?:fromXML|readClassAndObject|readObject|unserialize)|(?:\\w+\\.)?(?:SerializationUtils\\.deserialize)'),
    when: (c) => c.isNew || /(?:fromXML|readClassAndObject|deserialize|unserialize)$/.test(c.callee) }),
  call({ ...DESER, id: 'deser-jvm-yaml', langs: JVM, what: 'loads YAML with SnakeYAML default constructor, which instantiates arbitrary classes', args: [0], chain: true, callee: /^(?:(?:new\s*)?Yaml\(\)|yaml|snakeYaml|snake)\.(?:load|loadAll|loadAs)$|^Yaml\(\)\.(?:load|loadAll|loadAs)$/, when: (c, f) => !/SafeConstructor|setTagInspector|TagInspector|new\s+Yaml\(\s*new\s+SafeConstructor/.test(f.ctx.literal) }),
  call({ ...DESER, id: 'deser-csharp', langs: ['csharp'], what: deserWhat, args: 'any',
    callee: /(?:^|\.)(?:BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter|ObjectStateFormatter)\.(?:Deserialize|UnsafeDeserialize)$|^(?:formatter|bf|binaryFormatter|netSerializer|soapFormatter|los|osf)\.(?:Deserialize|UnsafeDeserialize)$|^(?:_?formatter|_?bf)\.Deserialize$/ }),
  call({ ...DESER, id: 'deser-csharp-json', langs: ['csharp'], what: 'deserializes JSON with TypeNameHandling enabled, which instantiates attacker-chosen types', args: [0], callee: x('(?:JsonConvert\\.DeserializeObject|JsonSerializer\\.Deserialize|\\w+\\.Deserialize|JsonConvert\\.DeserializeAnonymousType)'),
    when: (c, f) => /TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)|TypeNameHandling\.(?:All|Auto|Objects|Arrays)/.test(f.ctx.literal) }),
  call({ ...DESER, id: 'deser-swift', langs: ['swift'], what: 'unarchives untrusted data without secure coding (NSKeyedUnarchiver)', args: [0], callee: x('NSKeyedUnarchiver\\.(?:unarchiveObject|unarchiveTopLevelObjectWithData|unarchiveObjectWithFile|unarchiveObject\\(with)') }),
  call({ ...DESER, id: 'deser-kotlin-gson', langs: ['kotlin', 'java'], what: 'enables polymorphic typing on untrusted JSON (Jackson default typing)', need: 'always', conf: 'medium', args: 'any', allowNoArgs: true, sev: 'high', callee: x('(?:\\w+\\.)?(?:enableDefaultTyping|activateDefaultTyping)'), desc: 'Jackson default typing lets the JSON choose which class to instantiate, enabling gadget-chain deserialization attacks.' }),
];

// ═══ Code injection / dangerous eval ═════════════════════════════════════════
const CODE = { cls: 'code injection / dangerous eval', group: 'code', sev: 'critical', fix: 'Never evaluate input as code. Replace eval/exec with a parser or a lookup table of permitted operations; if dynamic dispatch is needed, map input to an allowlist of function names.' };
const codeWhat = 'evaluates it as code';
const FN_VALUE = /^\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[\w$]+\s*=>)/;

const CODE_RULES = [
  call({ ...CODE, id: 'code-js-eval', langs: ['js'], what: codeWhat, args: [0], callee: x('eval|Function|vm\\.runInContext|vm\\.runInNewContext|vm\\.runInThisContext|vm\\.Script|vm\\.compileFunction|execScript|new\\.Function|window\\.eval|globalThis\\.eval|(?:\\w+\\.)?runInNewContext'), when: notDot }),
  call({ ...CODE, id: 'code-js-timer', langs: ['js'], what: 'evaluates a string passed to a timer as code', args: [0], callee: x('setTimeout|setInterval|setImmediate'), argUnless: FN_VALUE, when: notDot }),
  call({ ...CODE, id: 'code-js-require', langs: ['js'], what: 'loads an arbitrary module chosen by the input (dynamic require/import)', sev: 'high', args: [0], callee: x('require|import|Module\\._load'), when: notDot }),
  call({ ...CODE, id: 'code-python', langs: ['python'], what: codeWhat, args: [0], callee: x('eval|exec|compile|__import__|execfile|importlib\\.import_module|runpy\\.run_path|runpy\\.run_module|builtins\\.eval|builtins\\.exec|code\\.interact|(?:\\w+\\.)?runsource'), when: notDot }),
  call({ ...CODE, id: 'code-php', langs: ['php'], what: codeWhat, args: [0], callee: x('eval|assert|create_function|preg_replace_callback_array') }),
  call({ ...CODE, id: 'code-php-callback', langs: ['php'], what: 'calls a function whose name is chosen by the input', args: [0], callee: x('call_user_func|call_user_func_array|forward_static_call|forward_static_call_array|array_map|array_reduce|iterator_apply|register_shutdown_function|register_tick_function|is_callable'), sev: 'high' }),
  call({ ...CODE, id: 'code-php-callback1', langs: ['php'], what: 'calls a function whose name is chosen by the input', args: [1], callee: x('array_filter|usort|uasort|uksort|array_walk|array_walk_recursive'), sev: 'high' }),
  call({ ...CODE, id: 'code-ruby', langs: ['ruby'], what: codeWhat, args: [0], callee: x('eval|instance_eval|class_eval|module_eval|instance_exec|class_exec|binding\\.eval|Kernel\\.eval|ERB\\.new|Object\\.const_get|const_get|Kernel\\.const_get'), when: (c) => !(c.name === 'eval' && c.viaDot) }),
  call({ ...CODE, id: 'code-ruby-send', langs: ['ruby'], what: 'invokes a method chosen by the input (send/public_send)', sev: 'high', args: [0], callee: m('send|public_send|__send__|try') , when: (c) => /(?:^|\.)(?:send|public_send|__send__)$/.test(c.callee) }),
  call({ ...CODE, id: 'code-swift', langs: ['swift'], what: codeWhat, args: 'any', callee: x('NSExpression|NSPredicate|(?:\\w+\\.)?evaluateScript'), when: (c) => /\bformat\s*:|evaluateScript/.test(c.text) }),
  call({ ...CODE, id: 'code-dart', langs: ['dart'], what: codeWhat, args: [0], callee: x('(?:\\w+\\.)?(?:evaluate|eval|evalJavascript|runCode)|Function\\.apply'), when: (c) => /^(?:\w+\.)?(?:evaluate|eval|evalJavascript|runCode)$/.test(c.callee) && /(?:js|javascript|runtime|interpreter)/i.test(c.callee + c.text.slice(0, 80)) || /Function\.apply/.test(c.callee) }),
];

// Variable-function call in PHP: $fn(...) where $fn is attacker-controlled
const PHP_VARFN = custom({ ...CODE, id: 'code-php-varfn', langs: ['php'], sev: 'high',
  run(flow, emit) {
    for (const c of flow.ctx.calls) {
      if (!/^\$\w+$/.test(c.callee)) continue;
      const st = flow.state(c.callee, '', c.line).filter(s => !isCleared(s, 'code'));
      if (st.length) emit(c.start, { title: 'code injection / dangerous eval', desc: `The function that is called is chosen by ${st[0].origin || 'parameter "' + st[0].param + '"'} (variable function call), allowing arbitrary function invocation.`, flowInfo: st[0].kind === 'src' ? { kind: 'src', origin: st[0].origin } : { kind: 'param', params: st } });
    }
  } });
const RUBY_CONSTANTIZE = custom({ ...CODE, id: 'code-ruby-constantize', langs: ['ruby'], sev: 'high',
  run(flow, emit) {
    for (const ll of flow.ctx.logical) {
      const mm = /([\w@$.\[\]]+(?:\([^)]*\))?)\.(?:constantize|safe_constantize)\b/.exec(ll.text);
      if (!mm) continue;
      const st = flow.state(mm[1], '', ll.line).filter(s => !isCleared(s, 'code'));
      if (st.length) emit(ll.start + mm.index, { desc: `constantize() turns ${st[0].origin || 'parameter "' + st[0].param + '"'} into a class, letting the caller choose which class is instantiated or invoked.`, flowInfo: st[0].kind === 'src' ? { kind: 'src', origin: st[0].origin } : { kind: 'param', params: st } });
    }
  } });

export const INJECTION_RULES = [...SQL_RULES, ...CMD_RULES, ...PATH_RULES, ...DESER_RULES, ...CODE_RULES, PHP_VARFN, RUBY_CONSTANTIZE];
export { m, x, notDot, kw, FN_VALUE, ALLL, WEB };
