```rust
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

const LOGS_DIR: &str = "/var/log/aegira";
const LOG_FILE_PATH: &str = "/var/log/aegira/system.log";
const INCIDENT_LOG_PATH: &str = "/var/log/aegira/incident.log";

const BUILTIN_RULES_DIR: &str = "/etc/aegira/rules/builtin";
const CUSTOM_RULES_DIR: &str = "/etc/aegira/rules/custom";

const POLL_INTERVAL_SECS: u64 = 2;
const RULE_RELOAD_INTERVAL_SECS: u64 = 10;
const COMMAND_TIMEOUT_SECS: u64 = 20;
const VERIFY_DELAY_SECS: u64 = 2;
const MAX_VERIFY_ATTEMPTS: u32 = 5;
const INCIDENT_COOLDOWN_SECS: u64 = 30;
const MAX_INCIDENT_LOG_BYTES: u64 = 10 * 1024 * 1024;

const MIN_MATCH_SCORE: i32 = 60;
const SELF_SERVICE: &str = "aegira";

#[derive(Debug, Deserialize, Clone)]
struct Rule {
    id: String,
    name: String,

    #[serde(default)]
    #[allow(dead_code)]
    severity: String,

    #[serde(default)]
    error_patterns: Vec<String>,

    #[serde(default)]
    context_patterns: Vec<String>,

    remediation: Remediation,
    verification: Verification,

    #[serde(default)]
    priority: i32,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type")]
enum Remediation {
    #[serde(rename = "service_restart")]
    ServiceRestart { service: String },

    #[serde(rename = "container_restart")]
    ContainerRestart { container: String },
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type")]
enum Verification {
    #[serde(rename = "service_active")]
    ServiceActive { service: String },

    #[serde(rename = "container_running")]
    ContainerRunning { container: String },

    #[serde(rename = "none")]
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

fn get_aegira_dir() -> PathBuf {
    PathBuf::from("/etc/aegira")
}

fn ensure_file_exists(path: &Path) -> Result<(), String> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map(|_| ())
        .map_err(|e| {
            format!(
                "Failed to create {}: {}",
                path.display(),
                e
            )
        })
}

fn ensure_environment_setup() -> Result<(), String> {
    fs::create_dir_all(LOGS_DIR)
        .map_err(|e| {
            format!(
                "Failed to create {}: {}",
                LOGS_DIR,
                e
            )
        })?;

    fs::create_dir_all(BUILTIN_RULES_DIR)
        .map_err(|e| {
            format!(
                "Failed to create {}: {}",
                BUILTIN_RULES_DIR,
                e
            )
        })?;

    fs::create_dir_all(CUSTOM_RULES_DIR)
        .map_err(|e| {
            format!(
                "Failed to create {}: {}",
                CUSTOM_RULES_DIR,
                e
            )
        })?;

    ensure_file_exists(Path::new(LOG_FILE_PATH))?;
    ensure_file_exists(Path::new(INCIDENT_LOG_PATH))?;

    Ok(())
}

fn rotate_incident_log_if_needed() {
    let path = Path::new(INCIDENT_LOG_PATH);

    let size = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(_) => return,
    };

    if size < MAX_INCIDENT_LOG_BYTES {
        return;
    }

    let rotated =
        Path::new(LOGS_DIR).join("incident.log.1");

    let _ = fs::remove_file(&rotated);

    if let Err(e) = fs::rename(path, &rotated) {
        eprintln!(
            "[LOG ERROR] Failed to rotate incident log: {}",
            e
        );
        return;
    }

    let _ = ensure_file_exists(path);
}

fn log_incident(msg: &str) {
    println!("{}", msg);

    rotate_incident_log_if_needed();

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(INCIDENT_LOG_PATH)
    {
        let _ = writeln!(file, "{}", msg);
    }
}

fn validate_rule(rule: &Rule) -> Result<(), String> {
    if rule.id.trim().is_empty() {
        return Err(
            "Rule ID cannot be empty".to_string()
        );
    }

    if rule.name.trim().is_empty() {
        return Err(format!(
            "Rule '{}' has an empty name",
            rule.id
        ));
    }

    if rule.error_patterns.is_empty() {
        return Err(format!(
            "Rule '{}' has no error patterns",
            rule.id
        ));
    }

    for pattern in &rule.error_patterns {
        if pattern.trim().is_empty() {
            return Err(format!(
                "Rule '{}' contains an empty error pattern",
                rule.id
            ));
        }
    }

    match &rule.remediation {
        Remediation::ServiceRestart { service } => {
            if service.trim().is_empty() {
                return Err(format!(
                    "Rule '{}' has an empty service",
                    rule.id
                ));
            }

            let normalized =
                service
                    .trim()
                    .trim_end_matches(".service")
                    .to_lowercase();

            if normalized == SELF_SERVICE {
                return Err(format!(
                    "Rule '{}' attempts to restart Aegira itself",
                    rule.id
                ));
            }
        }

        Remediation::ContainerRestart { container } => {
            if container.trim().is_empty() {
                return Err(format!(
                    "Rule '{}' has an empty container",
                    rule.id
                ));
            }
        }
    }

    match &rule.verification {
        Verification::ServiceActive { service } => {
            if service.trim().is_empty() {
                return Err(format!(
                    "Rule '{}' has an empty verification service",
                    rule.id
                ));
            }
        }

        Verification::ContainerRunning { container } => {
            if container.trim().is_empty() {
                return Err(format!(
                    "Rule '{}' has an empty verification container",
                    rule.id
                ));
            }
        }

        Verification::None => {}
    }

    Ok(())
}

fn parse_rules(contents: &str) -> Result<Vec<Rule>, String> {
    let contents = contents.trim();

    if contents.is_empty() {
        return Ok(Vec::new());
    }

    if contents.starts_with('[') {
        serde_json::from_str::<Vec<Rule>>(contents)
            .map_err(|e| e.to_string())
    } else {
        serde_json::from_str::<Rule>(contents)
            .map(|rule| vec![rule])
            .map_err(|e| e.to_string())
    }
}

fn load_rules_from_directory(
    path: &Path,
) -> Vec<Rule> {
    let mut rules = Vec::new();

    if !path.exists() {
        return rules;
    }

    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,

        Err(e) => {
            log_incident(&format!(
                "[RULES ERROR] Failed to read {}: {}",
                path.display(),
                e
            ));

            return rules;
        }
    };

    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                == Some("json")
        })
        .collect();

    files.sort();

    for file_path in files {
        let contents =
            match fs::read_to_string(&file_path) {
                Ok(contents) => contents,

                Err(e) => {
                    log_incident(&format!(
                        "[RULES ERROR] Failed reading {}: {}",
                        file_path.display(),
                        e
                    ));

                    continue;
                }
            };

        let parsed =
            match parse_rules(&contents) {
                Ok(rules) => rules,

                Err(e) => {
                    log_incident(&format!(
                        "[RULES ERROR] Invalid JSON {}: {}",
                        file_path.display(),
                        e
                    ));

                    continue;
                }
            };

        for rule in parsed {
            match validate_rule(&rule) {
                Ok(()) => {
                    log_incident(&format!(
                        "[RULES] Loaded: {}",
                        rule.id
                    ));

                    rules.push(rule);
                }

                Err(e) => {
                    log_incident(&format!(
                        "[RULES ERROR] {}",
                        e
                    ));
                }
            }
        }
    }

    rules
}

fn get_hardcoded_default_rules() -> Vec<Rule> {
    vec![Rule {
        id: "connection_refused".to_string(),
        name: "Connection Refused".to_string(),
        severity: "high".to_string(),

        error_patterns: vec![
            "connection refused".to_string(),
        ],

        context_patterns: Vec::new(),

        remediation: Remediation::ServiceRestart {
            service: "cron".to_string(),
        },

        verification: Verification::ServiceActive {
            service: "cron".to_string(),
        },

        priority: 10,
    }]
}

fn load_all_rules() -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut seen_ids = HashSet::new();

    let builtin_dir =
        Path::new(BUILTIN_RULES_DIR);

    let builtin =
        load_rules_from_directory(builtin_dir);

    for rule in builtin {
        let id = rule.id.trim().to_lowercase();

        if seen_ids.insert(id) {
            rules.push(rule);
        }
    }

    let custom_dir =
        Path::new(CUSTOM_RULES_DIR);

    let custom =
        load_rules_from_directory(custom_dir);

    for rule in custom {
        let id = rule.id.trim().to_lowercase();

        if seen_ids.insert(id) {
            rules.push(rule);
        } else {
            log_incident(&format!(
                "[RULES] Duplicate rule ignored: {}",
                rule.id
            ));
        }
    }

    if rules.is_empty() {
        log_incident(
            "[RULES] No external rules loaded. Using fallback rule."
        );

        rules = get_hardcoded_default_rules();
    }

    rules.sort_by(|a, b| {
        b.priority.cmp(&a.priority)
    });

    log_incident(&format!(
        "[RULES] Total active rules: {}",
        rules.len()
    ));

    rules
}

fn contains_case_insensitive(
    text: &str,
    pattern: &str,
) -> bool {
    text.to_lowercase()
        .contains(&pattern.to_lowercase())
}

fn calculate_match_score(
    rule: &Rule,
    incident: &str,
) -> Option<i32> {
    let mut error_matches: usize = 0;
    let mut context_matches: usize = 0;

    for pattern in &rule.error_patterns {
        if contains_case_insensitive(
            incident,
            pattern,
        ) {
            error_matches += 1;
        }
    }

    if error_matches == 0 {
        return None;
    }

    for pattern in &rule.context_patterns {
        if contains_case_insensitive(
            incident,
            pattern,
        ) {
            context_matches += 1;
        }
    }

    let error_score =
        60i32
            + (error_matches
                .saturating_sub(1) as i32
                * 10);

    let context_score =
        context_matches as i32 * 10;

    let priority_score =
        rule.priority.clamp(-20, 20);

    Some(
        (error_score
            + context_score
            + priority_score)
            .clamp(0, 100)
    )
}

fn find_best_rule<'a>(
    rules: &'a [Rule],
    incident: &str,
) -> Option<(&'a Rule, i32)> {
    let mut best:
        Option<(&'a Rule, i32)> = None;

    for rule in rules {
        let score =
            match calculate_match_score(
                rule,
                incident,
            ) {
                Some(score) => score,
                None => continue,
            };

        if score < MIN_MATCH_SCORE {
            continue;
        }

        match best {
            None => {
                best = Some((rule, score));
            }

            Some((current_rule, current_score)) => {
                if score > current_score
                    || (
                        score == current_score
                            && rule.id.to_lowercase()
                                < current_rule.id.to_lowercase()
                    )
                {
                    best = Some((rule, score));
                }
            }
        }
    }

    best
}

fn find_binary<'a>(
    candidates: &'a [&'a str],
) -> Result<&'a str, String> {
    for candidate in candidates {
        if Path::new(candidate).exists() {
            return Ok(candidate);
        }
    }

    Err(format!(
        "Required binary not found. Checked: {}",
        candidates.join(", ")
    ))
}

fn systemctl_binary() -> Result<&'static str, String> {
    find_binary(&[
        "/usr/bin/systemctl",
        "/bin/systemctl",
    ])
}

fn docker_binary() -> Result<&'static str, String> {
    find_binary(&[
        "/usr/bin/docker",
        "/bin/docker",
        "/usr/local/bin/docker",
    ])
}

fn execute_command(
    executable: &str,
    args: &[&str],
) -> Result<(), String> {
    log_incident(&format!(
        "[EXEC] {} {}",
        executable,
        args.join(" ")
    ));

    let mut child =
        Command::new(executable)
            .args(args)
            .spawn()
            .map_err(|e| {
                format!(
                    "Failed to start {}: {}",
                    executable,
                    e
                )
            })?;

    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(());
                }

                return Err(format!(
                    "{} exited with status {}",
                    executable,
                    status
                ));
            }

            Ok(None) => {
                if start.elapsed()
                    >= Duration::from_secs(
                        COMMAND_TIMEOUT_SECS,
                    )
                {
                    let _ = child.kill();
                    let _ = child.wait();

                    return Err(format!(
                        "{} timed out after {} seconds",
                        executable,
                        COMMAND_TIMEOUT_SECS
                    ));
                }

                sleep(Duration::from_millis(100));
            }

            Err(e) => {
                return Err(format!(
                    "Failed waiting for {}: {}",
                    executable,
                    e
                ));
            }
        }
    }
}

fn perform_remediation(
    remediation: &Remediation,
) -> Result<(), String> {
    match remediation {
        Remediation::ServiceRestart { service } => {
            let normalized =
                service
                    .trim()
                    .trim_end_matches(".service")
                    .to_lowercase();

            if normalized == SELF_SERVICE {
                return Err(
                    "Refusing remediation: rule attempts to restart Aegira itself"
                        .to_string(),
                );
            }

            let systemctl =
                systemctl_binary()?;

            log_incident(&format!(
                "[RECOVERY] Restarting service: {}",
                service
            ));

            execute_command(
                systemctl,
                &["restart", service.trim()],
            )
        }

        Remediation::ContainerRestart { container } => {
            let docker =
                docker_binary()?;

            log_incident(&format!(
                "[RECOVERY] Restarting container: {}",
                container
            ));

            execute_command(
                docker,
                &["restart", container.trim()],
            )
        }
    }
}

fn verify_recovery(
    verification: &Verification,
) -> bool {
    match verification {
        Verification::None => {
            log_incident(
                "[VERIFY] No verification required",
            );

            true
        }

        Verification::ServiceActive { service } => {
            let systemctl =
                match systemctl_binary() {
                    Ok(path) => path,

                    Err(e) => {
                        log_incident(
                            &format!(
                                "[VERIFY ERROR] {}",
                                e
                            )
                        );

                        return false;
                    }
                };

            log_incident(&format!(
                "[VERIFY] Checking service: {}",
                service
            ));

            match Command::new(systemctl)
                .args([
                    "is-active",
                    service.trim(),
                ])
                .output()
            {
                Ok(output) => {
                    let active =
                        output.status.success()
                            && String::from_utf8_lossy(
                                &output.stdout,
                            )
                            .trim()
                            == "active";

                    if active {
                        log_incident(
                            "[VERIFY] Service is active",
                        );
                    } else {
                        log_incident(
                            "[VERIFY] Service is NOT active",
                        );
                    }

                    active
                }

                Err(e) => {
                    log_incident(
                        &format!(
                            "[VERIFY ERROR] {}",
                            e
                        )
                    );

                    false
                }
            }
        }

        Verification::ContainerRunning { container } => {
            let docker =
                match docker_binary() {
                    Ok(path) => path,

                    Err(e) => {
                        log_incident(
                            &format!(
                                "[VERIFY ERROR] {}",
                                e
                            )
                        );

                        return false;
                    }
                };

            log_incident(&format!(
                "[VERIFY] Checking container: {}",
                container
            ));

            match Command::new(docker)
                .args([
                    "inspect",
                    "-f",
                    "{{.State.Running}}",
                    container.trim(),
                ])
                .output()
            {
                Ok(output) => {
                    let running =
                        output.status.success()
                            && String::from_utf8_lossy(
                                &output.stdout,
                            )
                            .trim()
                            == "true";

                    if running {
                        log_incident(
                            "[VERIFY] Container is running",
                        );
                    } else {
                        log_incident(
                            "[VERIFY] Container is NOT running",
                        );
                    }

                    running
                }

                Err(e) => {
                    log_incident(
                        &format!(
                            "[VERIFY ERROR] {}",
                            e
                        )
                    );

                    false
                }
            }
        }
    }
}

fn recover_with_rule(
    rule: &Rule,
) -> Result<(), String> {
    log_incident(&format!(
        "[MATCH] Rule: {}",
        rule.name
    ));

    log_incident(&format!(
        "[MATCH] Rule ID: {}",
        rule.id
    ));

    perform_remediation(
        &rule.remediation,
    )?;

    sleep(Duration::from_secs(
        VERIFY_DELAY_SECS,
    ));

    for attempt in 1..=MAX_VERIFY_ATTEMPTS {
        log_incident(&format!(
            "[VERIFY] Verification attempt {}/{}",
            attempt,
            MAX_VERIFY_ATTEMPTS
        ));

        if verify_recovery(
            &rule.verification,
        ) {
            return Ok(());
        }

        if attempt < MAX_VERIFY_ATTEMPTS {
            sleep(Duration::from_secs(
                VERIFY_DELAY_SECS,
            ));
        }
    }

    Err(
        "Remediation executed but health verification failed"
            .to_string(),
    )
}

fn make_incident_key(
    rule: &Rule,
    incident: &str,
) -> String {
    format!(
        "{}:{}",
        rule.id.to_lowercase(),
        incident.to_lowercase()
    )
}

fn cleanup_cooldowns(
    cooldowns: &mut HashMap<String, Instant>,
) {
    let cooldown =
        Duration::from_secs(
            INCIDENT_COOLDOWN_SECS,
        );

    cooldowns.retain(
        |_, timestamp| {
            timestamp.elapsed() < cooldown
        },
    );
}

fn process_incident(
    rules: &[Rule],
    incident: &str,
    cooldowns: &mut HashMap<String, Instant>,
) {
    cleanup_cooldowns(cooldowns);

    let start = Instant::now();

    log_incident(&format!(
        "[WATCHER] Incident detected: {}",
        incident
    ));

    let (rule, score) =
        match find_best_rule(
            rules,
            incident,
        ) {
            Some(result) => result,

            None => {
                log_incident(
                    "[MATCH] No known remediation rule found",
                );

                log_incident(
                    "[MANUAL ACTION] Unknown incident requires investigation",
                );

                return;
            }
        };

    let key =
        make_incident_key(
            rule,
            incident,
        );

    if cooldowns.contains_key(&key) {
        log_incident(&format!(
            "[COOLDOWN] Duplicate incident skipped for rule '{}'",
            rule.id
        ));

        return;
    }

    cooldowns.insert(
        key,
        Instant::now(),
    );

    log_incident(&format!(
        "[MATCH] Rule: {}",
        rule.name
    ));

    log_incident(&format!(
        "[MATCH] Confidence score: {}",
        score
    ));

    match recover_with_rule(rule) {
        Ok(()) => {
            log_incident(&format!(
                "[RESOLVED] Incident automatically recovered in {:.2?}",
                start.elapsed()
            ));
        }

        Err(e) => {
            log_incident(&format!(
                "[RECOVERY FAILED] {}",
                e
            ));

            log_incident(&format!(
                "[MANUAL ACTION] Rule '{}' requires intervention",
                rule.id
            ));
        }
    }
}

#[cfg(unix)]
fn get_file_identity(
    path: &Path,
) -> Result<FileIdentity, String> {
    use std::os::unix::fs::MetadataExt;

    let metadata =
        fs::metadata(path)
            .map_err(|e| {
                format!(
                    "Failed to read metadata for {}: {}",
                    path.display(),
                    e
                )
            })?;

    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn get_file_identity(
    path: &Path,
) -> Result<FileIdentity, String> {
    let metadata =
        fs::metadata(path)
            .map_err(|e| {
                format!(
                    "Failed to read metadata for {}: {}",
                    path.display(),
                    e
                )
            })?;

    Ok(FileIdentity {
        device: 0,
        inode: metadata.len(),
    })
}

fn main() {
    if let Err(e) =
        ensure_environment_setup()
    {
        eprintln!(
            "[FATAL] Environment setup failed: {}",
            e
        );

        return;
    }

    let aegira_dir =
        get_aegira_dir();

    log_incident(
        "[INFO] Aegira Recovery Engine Started",
    );

    log_incident(&format!(
        "[INFO] Aegira directory: {}",
        aegira_dir.display()
    ));

    log_incident(&format!(
        "[INFO] Monitoring log: {}",
        LOG_FILE_PATH
    ));

    let mut rules =
        load_all_rules();

    log_incident(&format!(
        "[INFO] {} remediation rules ready",
        rules.len()
    ));

    let mut last_rule_reload =
        Instant::now();

    let log_path =
        Path::new(LOG_FILE_PATH);

    let mut position =
        match fs::metadata(log_path) {
            Ok(metadata) => metadata.len(),

            Err(e) => {
                log_incident(
                    &format!(
                        "[FATAL] Failed to inspect monitored log: {}",
                        e
                    )
                );

                return;
            }
        };

    let mut file_identity =
        match get_file_identity(log_path) {
            Ok(identity) => identity,

            Err(e) => {
                log_incident(
                    &format!(
                        "[FATAL] {}",
                        e
                    )
                );

                return;
            }
        };

    let mut cooldowns:
        HashMap<String, Instant> =
        HashMap::new();

    log_incident(
        "[INFO] Monitoring new log entries...",
    );

    loop {
        if last_rule_reload.elapsed()
            >= Duration::from_secs(
                RULE_RELOAD_INTERVAL_SECS,
            )
        {
            rules =
                load_all_rules();

            last_rule_reload =
                Instant::now();

            log_incident(&format!(
                "[RULES] Rules reloaded: {} active",
                rules.len()
            ));
        }

        let metadata =
            match fs::metadata(log_path) {
                Ok(metadata) => metadata,

                Err(e) => {
                    log_incident(
                        &format!(
                            "[LOG ERROR] Failed to stat monitored log: {}",
                            e
                        )
                    );

                    sleep(
                        Duration::from_secs(
                            POLL_INTERVAL_SECS,
                        )
                    );

                    continue;
                }
            };

        let current_identity =
            match get_file_identity(log_path) {
                Ok(identity) => identity,

                Err(e) => {
                    log_incident(
                        &format!(
                            "[LOG ERROR] {}",
                            e
                        )
                    );

                    sleep(
                        Duration::from_secs(
                            POLL_INTERVAL_SECS,
                        )
                    );

                    continue;
                }
            };

        let file_size =
            metadata.len();

        if current_identity
            != file_identity
        {
            log_incident(
                "[INFO] Log rotation detected. Resetting position.",
            );

            file_identity =
                current_identity;

            position = 0;
        } else if file_size < position {
            log_incident(
                "[INFO] Log truncation detected. Resetting position.",
            );

            position = 0;
        }

        if file_size <= position {
            sleep(
                Duration::from_secs(
                    POLL_INTERVAL_SECS,
                )
            );

            continue;
        }

        let file =
            match File::open(log_path) {
                Ok(file) => file,

                Err(e) => {
                    log_incident(
                        &format!(
                            "[LOG ERROR] Failed opening monitored log: {}",
                            e
                        )
                    );

                    sleep(
                        Duration::from_secs(
                            POLL_INTERVAL_SECS,
                        )
                    );

                    continue;
                }
            };

        let mut reader =
            BufReader::new(file);

        if let Err(e) =
            reader.seek(
                SeekFrom::Start(position)
            )
        {
            log_incident(
                &format!(
                    "[LOG ERROR] Failed seeking monitored log: {}",
                    e
                )
            );

            sleep(
                Duration::from_secs(
                    POLL_INTERVAL_SECS,
                )
            );

            continue;
        }

        loop {
            let line_start =
                position;

            let mut line =
                String::new();

            let bytes_read =
                match reader.read_line(
                    &mut line,
                ) {
                    Ok(bytes) => bytes,

                    Err(e) => {
                        log_incident(
                            &format!(
                                "[LOG ERROR] Failed reading monitored log: {}",
                                e
                            )
                        );

                        break;
                    }
                };

            if bytes_read == 0 {
                break;
            }

            if !line.ends_with('\n') {
                position = line_start;
                break;
            }

            position =
                line_start
                    + bytes_read as u64;

            let trimmed =
                line.trim();

            if trimmed.contains("[ERROR]")
                || trimmed.contains("[CRITICAL]")
            {
                process_incident(
                    &rules,
                    trimmed,
                    &mut cooldowns,
                );
            }
        }

        sleep(
            Duration::from_secs(
                POLL_INTERVAL_SECS,
            )
        );
    }
}
```
