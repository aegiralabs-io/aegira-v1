# Aegira v0.2

## Build
cargo build --release

## Install
sudo ./target/release/aegira install

The installer:
- installs the binary to /usr/local/bin/aegira
- installs the bundled rules.json to /etc/aegira/rules.json
- creates /etc/aegira/config.json
- creates /var/log/aegira/
- creates and enables the systemd service
- asks for the service and log file to monitor

## Commands
aegira install
aegira run
aegira status
aegira show-rules

## Safety
Aegira does not execute arbitrary shell commands. Supported remediation is limited to service restart, container restart (non-Free modes), and alert-only rules.
Recovery attempts are bounded by max_recovery_attempts within recovery_window_secs.
