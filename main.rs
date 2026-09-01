use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CONFIG_DIR: &str = "/etc/aegira";
const RULES_PATH: &str = "/etc/aegira/rules.json";
const LOGS_DIR: &str = "/var/log/aegira";
const AEGIRA_LOG: &str = "/var/log/aegira/aegira.log";
const INCIDENT_LOG: &str = "/var/log/aegira/incident.log";
const INSTALL_BIN: &str = "/usr/local/bin/aegira";
const SYSTEMD_UNIT: &str = "/etc/systemd/system/aegira.service";
const CONFIG_PATH: &str = "/etc/aegira/config.json";

const POLL_SECS: u64 = 2;
const RULE_RELOAD_SECS: u64 = 10;
const COMMAND_TIMEOUT_SECS: u64 = 20;
const VERIFY_DELAY_SECS: u64 = 2;
const MAX_VERIFY_ATTEMPTS: u32 = 5;
const INCIDENT_COOLDOWN_SECS: u64 = 30;
const MAX_RECOVERY_ATTEMPTS: u32 = 3;
const RECOVERY_WINDOW_SECS: u64 = 300;
const MAX_INCIDENT_LOG_BYTES: u64 = 10 * 1024 * 1024;
const SELF_SERVICE: &str = "aegira";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    mode: String,
    service: String,
    log_path: String,
    max_recovery_attempts: u32,
    recovery_window_secs: u64,
    incident_cooldown_secs: u64,
    email_enabled: bool,
    email_to: Option<String>,
    email_from: Option<String>,
    email_command: Option<String>,
    #[serde(default)]
    container: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: "free".into(),
            service: String::new(),
            log_path: String::new(),
            max_recovery_attempts: MAX_RECOVERY_ATTEMPTS,
            recovery_window_secs: RECOVERY_WINDOW_SECS,
            incident_cooldown_secs: INCIDENT_COOLDOWN_SECS,
            email_enabled: false,
            email_to: None,
            email_from: None,
            email_command: None,
            container: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Rule {
    id: String,
    name: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    error_patterns: Vec<String>,
    #[serde(default)]
    context_patterns: Vec<String>,
    remediation: Remediation,
    verification: Verification,
    #[serde(default)]
    priority: i32,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

fn default_enabled() -> bool { true }

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
enum Remediation {
    #[serde(rename = "service_restart")]
    ServiceRestart { service: String },
    #[serde(rename = "container_restart")]
    ContainerRestart { container: String },
    #[serde(rename = "alert_only")]
    AlertOnly,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
enum Verification {
    #[serde(rename = "service_active")]
    ServiceActive { service: String },
    #[serde(rename = "container_running")]
    ContainerRunning { container: String },
    #[serde(rename = "none")]
    None,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity { dev: u64, ino: u64 }

struct RuleLoadResult {
    rules: Vec<Rule>,
    files_found: usize,
    errors: usize,
}

#[derive(Clone, Copy)]
struct RecoveryStamp { at: Instant }

fn now_string() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    secs.to_string()
}

fn log_line(path: &Path, msg: &str) {
    let _ = fs::create_dir_all(LOGS_DIR);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "[{}] {}", now_string(), msg);
    }
}

fn log(msg: &str) {
    println!("{}", msg);
    log_line(Path::new(AEGIRA_LOG), msg);
}

fn incident(msg: &str) {
    println!("{}", msg);
    rotate_incident_log();
    log_line(Path::new(INCIDENT_LOG), msg);
}

fn rotate_incident_log() {
    let p = Path::new(INCIDENT_LOG);
    if let Ok(m) = fs::metadata(p) {
        if m.len() >= MAX_INCIDENT_LOG_BYTES {
            let rotated = Path::new(LOGS_DIR).join("incident.log.1");
            let _ = fs::remove_file(&rotated);
            let _ = fs::rename(p, rotated);
        }
    }
}

fn require_root() -> Result<(), String> {
    let output = Command::new("id").args(["-u"]).output().map_err(|e| e.to_string())?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != "0" {
        return Err("This operation requires root. Run it with sudo.".into());
    }
    Ok(())
}

fn find_binary(names: &[&str]) -> Result<&'static str, String> {
    for n in names {
        if Path::new(n).exists() { return Ok(n); }
    }
    Err(format!("Required binary not found. Checked: {}", names.join(", ")))
}

fn systemctl() -> Result<&'static str, String> {
    find_binary(&["/usr/bin/systemctl", "/bin/systemctl"])
}

fn docker() -> Result<&'static str, String> {
    find_binary(&["/usr/bin/docker", "/bin/docker", "/usr/local/bin/docker"])
}

fn normalize_service(s: &str) -> String {
    s.trim().trim_end_matches(".service").to_lowercase()
}

fn is_self_service(s: &str) -> bool {
    normalize_service(s) == SELF_SERVICE
}

fn normalize_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut space = false;
    for ch in s.chars().flat_map(|c| c.to_lowercase()) {
        if ch.is_whitespace() {
            if !space { out.push(' '); space = true; }
        } else {
            out.push(ch);
            space = false;
        }
    }
    out.trim().to_string()
}

fn contains_normalized(text: &str, pattern: &str) -> bool {
    let t = normalize_text(text);
    let p = normalize_text(pattern);
    !p.is_empty() && t.contains(&p)
}

fn validate_rule(rule: &Rule, mode: &str) -> Result<(), String> {
    if rule.id.trim().is_empty() || rule.name.trim().is_empty() {
        return Err(format!("Rule '{}' has an empty id/name", rule.id));
    }
    if rule.error_patterns.is_empty() || rule.error_patterns.iter().any(|p| p.trim().is_empty()) {
        return Err(format!("Rule '{}' has invalid error patterns", rule.id));
    }
    match &rule.remediation {
        Remediation::ServiceRestart { service } => {
            if service.trim().is_empty() || is_self_service(service) {
                return Err(format!("Rule '{}' has invalid service remediation", rule.id));
            }
        }
        Remediation::ContainerRestart { container } => {
            if container.trim().is_empty() { return Err(format!("Rule '{}' has empty container", rule.id)); }
            if mode == "free" { return Ok(()); }
        }
        Remediation::AlertOnly => {}
    }
    Ok(())
}

fn parse_rules(s: &str) -> Result<Vec<Rule>, String> {
    if s.trim().starts_with('[') {
        serde_json::from_str::<Vec<Rule>>(s).map_err(|e| e.to_string())
    } else {
        serde_json::from_str::<Rule>(s).map(|r| vec![r]).map_err(|e| e.to_string())
    }
}

fn load_rules(path: &Path, mode: &str) -> RuleLoadResult {
    let mut r = RuleLoadResult { rules: Vec::new(), files_found: 0, errors: 0 };
    if !path.exists() {
        log(&format!("[RULES ERROR] Missing {}", path.display()));
        r.errors += 1;
        return r;
    }
    let text = match fs::read_to_string(path) {
        Ok(x) => x,
        Err(e) => {
            log(&format!("[RULES ERROR] Cannot read {}: {}", path.display(), e));
            r.errors += 1;
            return r;
        }
    };
    r.files_found = 1;
    let parsed = match parse_rules(&text) {
        Ok(x) => x,
        Err(e) => {
            log(&format!("[RULES ERROR] Invalid JSON: {}", e));
            r.errors += 1;
            return r;
        }
    };
    let mut seen = HashSet::new();
    for rule in parsed {
        if !rule.enabled { continue; }
        if matches!(rule.remediation, Remediation::ContainerRestart { .. }) && mode == "free" {
            continue;
        }
        if let Err(e) = validate_rule(&rule, mode) {
            log(&format!("[RULES ERROR] {}", e));
            r.errors += 1;
            continue;
        }
        let id = rule.id.trim().to_lowercase();
        if seen.insert(id) { r.rules.push(rule); }
        else { log(&format!("[RULES ERROR] Duplicate rule '{}' ignored", rule.id)); }
    }
    r.rules.sort_by(|a,b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));
    r
}

fn replace_target(value: &str, config: &Config) -> String {
    if value == "TARGET_SERVICE" { config.service.clone() }
    else if value == "TARGET_CONTAINER" { config.container.clone().unwrap_or_default() }
    else { value.to_string() }
}

fn score(rule: &Rule, text: &str) -> Option<i32> {
    let errors = rule.error_patterns.iter().filter(|p| contains_normalized(text, p)).count();
    if errors == 0 { return None; }
    let contexts = rule.context_patterns.iter().filter(|p| contains_normalized(text, p)).count();
    Some((60 + ((errors.saturating_sub(1)) as i32 * 10) + (contexts as i32 * 10) + rule.priority.clamp(-20,20)).clamp(0,100))
}

fn best_rule<'a>(rules: &'a [Rule], text: &str) -> Option<(&'a Rule, i32)> {
    rules.iter().filter_map(|r| score(r,text).map(|s|(r,s))).filter(|(_,s)|*s>=60).max_by(|(a,sa),(b,sb)| sa.cmp(sb).then_with(|| b.priority.cmp(&a.priority)).then_with(|| b.id.cmp(&a.id)))
}

fn run_command(exe: &str, args: &[&str]) -> Result<(), String> {
    log(&format!("[EXEC] {} {}", exe, args.join(" ")));
    let mut child = Command::new(exe).args(args).stdout(Stdio::null()).stderr(Stdio::null()).spawn()
        .map_err(|e| format!("Failed to start {}: {}", exe, e))?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(s)) if s.success() => return Ok(()),
            Ok(Some(s)) => return Err(format!("{} exited with {}", exe, s)),
            Ok(None) if start.elapsed() >= Duration::from_secs(COMMAND_TIMEOUT_SECS) => {
                let _ = child.kill(); let _ = child.wait();
                return Err(format!("{} timed out after {} seconds", exe, COMMAND_TIMEOUT_SECS));
            }
            Ok(None) => sleep(Duration::from_millis(100)),
            Err(e) => return Err(format!("Failed waiting for {}: {}", exe, e)),
        }
    }
}

fn remediation(r: &Remediation, config: &Config) -> Result<(), String> {
    match r {
        Remediation::AlertOnly => Ok(()),
        Remediation::ServiceRestart { service } => {
            let target = replace_target(service, config);
            if target.trim().is_empty() || is_self_service(&target) { return Err("Refusing invalid/self service target".into()); }
            run_command(systemctl()?, &["restart", target.trim()])
        }
        Remediation::ContainerRestart { container } => {
            if config.mode == "free" { return Err("Container remediation unavailable in Free mode".into()); }
            let target = replace_target(container, config);
            if target.trim().is_empty() { return Err("Empty container target".into()); }
            run_command(docker()?, &["restart", target.trim()])
        }
    }
}

fn verify(v: &Verification, config: &Config) -> bool {
    match v {
        Verification::None => true,
        Verification::ServiceActive { service } => {
            let target = replace_target(service, config);
            match Command::new(systemctl().unwrap_or("/usr/bin/systemctl")).args(["is-active", target.trim()]).output() {
                Ok(o) => o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "active",
                Err(_) => false,
            }
        }
        Verification::ContainerRunning { container } => {
            if config.mode == "free" { return false; }
            let target = replace_target(container, config);
            match Command::new(docker().unwrap_or("/usr/bin/docker")).args(["inspect","-f","{{.State.Running}}",target.trim()]).output() {
                Ok(o) => o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "true",
                Err(_) => false,
            }
        }
    }
}

fn send_email(config: &Config, subject: &str, body: &str) {
    if !config.email_enabled { return; }
    let (Some(to), Some(from), Some(cmd)) = (&config.email_to, &config.email_from, &config.email_command) else {
        incident("[ALERT ERROR] Email is enabled but email_to/email_from/email_command is incomplete");
        return;
    };
    let mut child = match Command::new(cmd).args([to]).stdin(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(e) => { incident(&format!("[ALERT ERROR] Failed to start email command: {}", e)); return; }
    };
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = writeln!(stdin, "From: {}", from);
        let _ = writeln!(stdin, "To: {}", to);
        let _ = writeln!(stdin, "Subject: {}", subject);
        let _ = writeln!(stdin);
        let _ = writeln!(stdin, "{}", body);
    }
    let _ = child.wait();
}

fn alert(config: &Config, subject: &str, body: &str) {
    incident(&format!("[ALERT] {} | {}", subject, body));
    send_email(config, subject, body);
}

fn looks_like_incident(text: &str, rules: &[Rule]) -> bool {
    let normalized = normalize_text(text);
    if normalized.is_empty() { return false; }

    // Never require a literal "[ERROR]" or "[CRITICAL]" marker.
    // First, let the actual rule library decide whether this line contains
    // a known failure pattern.
    if rules.iter().any(|r| score(r, text).is_some()) {
        return true;
    }

    // Unknown failures should still be visible, but ordinary INFO/DEBUG logs
    // must not become alerts. These markers are deliberately conservative.
    const MARKERS: &[&str] = &[
        " error ", " critical ", " fatal ", " exception ",
        " panic ", " failed ", " failure ", " fatal:",
        " traceback", " stack trace", " crash", " crashed",
        " oom", " out-of-memory"
    ];

    let padded = format!(" {} ", normalized);
    MARKERS.iter().any(|m| padded.contains(m))
}

fn process_incident(config: &Config, rules: &[Rule], text: &str, cooldowns: &mut HashMap<String, Instant>, recovery_history: &mut HashMap<String, Vec<RecoveryStamp>>) {
    incident(&format!("[DETECTED] {}", text));
    let Some((rule, match_score)) = best_rule(rules, text) else {
        alert(config, "Aegira: unknown incident", &format!("No active rule matched: {}", text));
        return;
    };
    let key = rule.id.to_lowercase();
    let now = Instant::now();
    cooldowns.retain(|_, t| t.elapsed() < Duration::from_secs(config.incident_cooldown_secs));
    if cooldowns.contains_key(&key) {
        incident(&format!("[COOLDOWN] Rule '{}' skipped", rule.id));
        return;
    }
    cooldowns.insert(key.clone(), now);
    incident(&format!("[MATCH] {} | severity={} | score={}", rule.name, rule.severity, match_score));

    if matches!(rule.remediation, Remediation::AlertOnly) {
        alert(config, &format!("Aegira alert-only rule: {}", rule.name), text);
        return;
    }

    let history = recovery_history.entry(key.clone()).or_default();
    history.retain(|s| s.at.elapsed() < Duration::from_secs(config.recovery_window_secs));
    if history.len() >= config.max_recovery_attempts as usize {
        alert(config, &format!("Aegira recovery limit exceeded: {}", rule.name), &format!("Recovery stopped after {} attempts in {} seconds. Incident: {}", config.max_recovery_attempts, config.recovery_window_secs, text));
        return;
    }

    history.push(RecoveryStamp { at: now });
    let started = Instant::now();
    match remediation(&rule.remediation, config) {
        Err(e) => {
            alert(config, &format!("Aegira recovery failed: {}", rule.name), &format!("Remediation failed: {} | Incident: {}", e, text));
        }
        Ok(()) => {
            sleep(Duration::from_secs(VERIFY_DELAY_SECS));
            let mut ok = false;
            for attempt in 1..=MAX_VERIFY_ATTEMPTS {
                incident(&format!("[VERIFY] {} attempt {}/{}", rule.id, attempt, MAX_VERIFY_ATTEMPTS));
                if verify(&rule.verification, config) { ok = true; break; }
                if attempt < MAX_VERIFY_ATTEMPTS { sleep(Duration::from_secs(VERIFY_DELAY_SECS)); }
            }
            if ok {
                incident(&format!("[RESOLVED] {} recovered in {:?}", rule.id, started.elapsed()));
            } else {
                alert(config, &format!("Aegira recovery unresolved: {}", rule.name), &format!("Remediation executed but verification failed. Incident: {}", text));
            }
        }
    }
}

fn ensure_file(path: &Path) -> Result<(), String> {
    OpenOptions::new().create(true).append(true).open(path).map(|_|()).map_err(|e| format!("{}: {}", path.display(), e))
}

fn prompt(label: &str, default: Option<&str>) -> String {
    print!("{}", label);
    if let Some(d) = default { print!(" [{}]", d); }
    print!(": ");
    let _ = io::stdout().flush();
    let mut s = String::new();
    let _ = io::stdin().read_line(&mut s);
    let s = s.trim().to_string();
    if s.is_empty() { default.unwrap_or("").to_string() } else { s }
}

fn write_config(config: &Config) -> Result<(), String> {
    fs::create_dir_all(CONFIG_DIR).map_err(|e| e.to_string())?;
    fs::write(CONFIG_PATH, serde_json::to_string_pretty(config).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

fn load_config() -> Result<Config, String> {
    let s = fs::read_to_string(CONFIG_PATH).map_err(|e| format!("Cannot read {}: {}", CONFIG_PATH, e))?;
    serde_json::from_str(&s).map_err(|e| format!("Invalid config: {}", e))
}

fn install() -> Result<(), String> {
    require_root()?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    fs::create_dir_all(CONFIG_DIR).map_err(|e| e.to_string())?;
    fs::create_dir_all(LOGS_DIR).map_err(|e| e.to_string())?;
    fs::copy(&exe, INSTALL_BIN).map_err(|e| format!("Cannot install binary: {}", e))?;
    fs::set_permissions(INSTALL_BIN, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;

    let bundled_rules = exe.parent().unwrap_or(Path::new(".")).join("rules.json");
    if !bundled_rules.exists() { return Err(format!("Bundled rules.json not found next to {}", exe.display())); }
    fs::copy(&bundled_rules, RULES_PATH).map_err(|e| format!("Cannot install rules.json: {}", e))?;

    let service = prompt("Service to monitor (systemd)", None);
    if service.trim().is_empty() || is_self_service(&service) { return Err("A valid non-Aegira service is required.".into()); }
    let log_path = prompt("Log file to monitor", Some("/var/log/aegira/system.log"));
    ensure_file(Path::new(&log_path))?;

    let mut config = Config::default();
    config.service = service.trim().to_string();
    config.log_path = log_path.trim().to_string();

    let email = prompt("Enable email alerts? (y/N)", Some("N"));
    if email.eq_ignore_ascii_case("y") {
        config.email_enabled = true;
        config.email_to = Some(prompt("Alert recipient email", None));
        config.email_from = Some(prompt("From address", Some("aegira@localhost")));
        config.email_command = Some(prompt("sendmail-compatible command", Some("/usr/sbin/sendmail")));
    }

    write_config(&config)?;

    let unit = format!(r#"[Unit]
Description=Aegira Automated Recovery Engine
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/aegira
ExecStart={}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"#, INSTALL_BIN);
    fs::write(SYSTEMD_UNIT, unit).map_err(|e| e.to_string())?;
    let ctl = systemctl()?;
    run_command(ctl, &["daemon-reload"])?;
    run_command(ctl, &["enable","aegira.service"])?;
    run_command(ctl, &["restart","aegira.service"])?;
    println!("Aegira installed and started.");
    Ok(())
}

fn file_identity(path: &Path) -> Result<FileIdentity, String> {
    let m = fs::metadata(path).map_err(|e| e.to_string())?;
    Ok(FileIdentity { dev: m.dev(), ino: m.ino() })
}

fn run() -> Result<(), String> {
    let mut config = load_config()?;
    if config.service.trim().is_empty() { return Err("No service configured.".into()); }
    if config.max_recovery_attempts == 0 { config.max_recovery_attempts = 1; }
    if config.recovery_window_secs == 0 { config.recovery_window_secs = RECOVERY_WINDOW_SECS; }

    log("[INFO] Aegira started");
    log(&format!("[INFO] Mode: {}", config.mode));
    log(&format!("[INFO] Monitoring service: {}", config.service));
    log(&format!("[INFO] Monitoring log: {}", config.log_path));

    let mut rules = load_rules(Path::new(RULES_PATH), &config.mode).rules;
    log(&format!("[INFO] {} active rules loaded", rules.len()));

    ensure_file(Path::new(&config.log_path))?;
    let mut position = fs::metadata(&config.log_path).map_err(|e| e.to_string())?.len();
    let mut identity = file_identity(Path::new(&config.log_path))?;
    let mut partial = String::new();
    let mut last_reload = Instant::now();
    let mut cooldowns: HashMap<String, Instant> = HashMap::new();
    let mut recovery_history: HashMap<String, Vec<RecoveryStamp>> = HashMap::new();

    loop {
        if last_reload.elapsed() >= Duration::from_secs(RULE_RELOAD_SECS) {
            let loaded = load_rules(Path::new(RULES_PATH), &config.mode);
            if loaded.errors == 0 && loaded.files_found > 0 {
                rules = loaded.rules;
                log(&format!("[RULES] Reloaded {} active rules", rules.len()));
            } else {
                log("[RULES] Reload rejected; keeping previous valid rule set");
            }
            last_reload = Instant::now();
        }

        ensure_file(Path::new(&config.log_path))?;
        let meta = fs::metadata(&config.log_path).map_err(|e| e.to_string())?;
        let new_id = FileIdentity { dev: meta.dev(), ino: meta.ino() };
        if new_id != identity || meta.len() < position {
            identity = new_id;
            position = 0;
            partial.clear();
            log("[INFO] Log replacement/truncation detected; watcher position reset");
        }

        if meta.len() > position {
            let file = File::open(&config.log_path).map_err(|e| e.to_string())?;
            let mut reader = BufReader::new(file);
            reader.seek(SeekFrom::Start(position)).map_err(|e| e.to_string())?;

            loop {
                let mut line = String::new();
                let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
                if n == 0 { break; }
                position += n as u64;
                partial.push_str(&line);
                if !partial.ends_with('\n') { continue; }

                let text = partial.trim().to_string();
                partial.clear();
                if !text.is_empty() && looks_like_incident(&text, &rules) {
                    process_incident(&config, &rules, &text, &mut cooldowns, &mut recovery_history);
                }
            }
        }
        sleep(Duration::from_secs(POLL_SECS));
    }
}

fn main() {
    let result = match std::env::args().nth(1).as_deref() {
        Some("install") => install(),
        Some("run") | None => run(),
        Some("show-rules") => {
            match load_config().and_then(|c| {
                let loaded = load_rules(Path::new(RULES_PATH), &c.mode);
                for r in loaded.rules {
                    println!("{} | {} | {} | {}", r.id, r.name, r.severity, r.enabled);
                }
                Ok(())
            }) { Ok(()) => Ok(()), Err(e) => Err(e) }
        }
        Some("status") => {
            match systemctl().and_then(|ctl| run_command(ctl, &["status","aegira.service","--no-pager"])) {
                Ok(()) => Ok(()), Err(e) => Err(e)
            }
        }
        Some(other) => Err(format!("Unknown command '{}'. Use: install | run | show-rules | status", other)),
    };
    if let Err(e) = result {
        eprintln!("[FATAL] {}", e);
        std::process::exit(1);
    }
}
