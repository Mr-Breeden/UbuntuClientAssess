#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

LOG_DIR="$SCRIPT_DIR/setup_logs"
LOG_FILE="$LOG_DIR/install_dependencies.log"
mkdir -p "$LOG_DIR"
: > "$LOG_FILE"
printf 'UbuntuClientAssess dependency setup log\nStarted: %s\n\n' "$(date -Is 2>/dev/null || date)" >> "$LOG_FILE"

TOTAL_STEPS=5
CORE_PACKAGES=(
  python3 python3-pip python3-venv file binutils iproute2 coreutils dpkg dpkg-dev
  git curl wget jq tree unzip zip p7zip-full tar xz-utils acl libcap2-bin
)
EXTRA_PACKAGES=(
  elfutils patchelf pax-utils checksec strace ltrace lsof procps psmisc
  inotify-tools net-tools dnsutils tcpdump nmap socat netcat-openbsd debsums
  apt-file auditd audispd-plugins dbus dbus-user-session libglib2.0-bin gdb
  binwalk yara sqlite3 desktop-file-utils shared-mime-info squashfs-tools
  gnupg debsig-verify debsigs flatpak
)

if [[ "${EUID}" -eq 0 ]]; then SUDO=(); else SUDO=(sudo); fi

step() { printf '[%s/%s] %-42s' "$1" "$TOTAL_STEPS" "$2"; }
pass() { printf ' PASS\n'; }
warn() { printf ' WARN\n'; }
fail() { printf ' FAIL\n'; }
log_section() { printf '\n===== %s =====\n' "$1" >> "$LOG_FILE"; }
run_logged() { "$@" >> "$LOG_FILE" 2>&1; }
show_failure_tail() {
  printf '\n%s\n' "$1" >&2
  printf 'Last log entries:\n' >&2
  tail -n 20 "$LOG_FILE" >&2 || true
  printf '\nDetailed log: %s\n' "$LOG_FILE" >&2
}

printf 'UbuntuClientAssess Dependency Setup\n===================================\n\n'
if ((${#SUDO[@]})); then
  printf 'Administrator privileges are required to install system packages.\n'
  if ! "${SUDO[@]}" -v; then
    printf '[FAIL] Unable to obtain administrator privileges.\n' >&2
    exit 1
  fi
  printf '\n'
fi

step 1 'APT package information'
log_section 'APT package information'
if run_logged "${SUDO[@]}" apt update; then pass; else fail; show_failure_tail 'Unable to update APT package information.'; exit 1; fi

step 2 'Required system packages'
log_section 'Required system packages'
if run_logged "${SUDO[@]}" apt install -y "${CORE_PACKAGES[@]}"; then pass; else fail; show_failure_tail 'Unable to install one or more required system packages.'; exit 1; fi

step 3 'Recommended/optional tools'
log_section 'Recommended/optional tools'
AVAILABLE_EXTRA=(); UNAVAILABLE_EXTRA=(); FAILED_EXTRA=()
for package in "${EXTRA_PACKAGES[@]}"; do
  if apt-cache show "$package" >/dev/null 2>> "$LOG_FILE"; then
    AVAILABLE_EXTRA+=("$package")
  else
    UNAVAILABLE_EXTRA+=("$package")
    printf '[INFO] Optional package unavailable in configured repositories: %s\n' "$package" >> "$LOG_FILE"
  fi
done
if ((${#AVAILABLE_EXTRA[@]})); then
  if ! run_logged "${SUDO[@]}" apt install -y "${AVAILABLE_EXTRA[@]}"; then
    printf '[WARN] Grouped optional install failed; retrying individually.\n' >> "$LOG_FILE"
    for package in "${AVAILABLE_EXTRA[@]}"; do
      if ! run_logged "${SUDO[@]}" apt install -y "$package"; then FAILED_EXTRA+=("$package"); fi
    done
  fi
fi
APT_FILE_WARNING=0
if command -v apt-file >/dev/null 2>&1; then
  if ! run_logged "${SUDO[@]}" apt-file update; then APT_FILE_WARNING=1; printf '[WARN] apt-file update failed.\n' >> "$LOG_FILE"; fi
fi
if ((${#UNAVAILABLE_EXTRA[@]} || ${#FAILED_EXTRA[@]} || APT_FILE_WARNING)); then warn; else pass; fi
if ((${#UNAVAILABLE_EXTRA[@]})); then printf '      [WARN] Optional packages unavailable:'; printf ' %s' "${UNAVAILABLE_EXTRA[@]}"; printf '\n'; fi
if ((${#FAILED_EXTRA[@]})); then printf '      [WARN] Optional packages not installed:'; printf ' %s' "${FAILED_EXTRA[@]}"; printf '\n'; fi
if ((APT_FILE_WARNING)); then printf '      [WARN] apt-file index update failed; continuing.\n'; fi

step 4 'Python virtual environment'
log_section 'Python virtual environment'
if [[ ! -d .venv ]]; then
  if run_logged python3 -m venv .venv; then pass; else fail; show_failure_tail 'Unable to create the Python virtual environment.'; exit 1; fi
else
  printf '[INFO] Reusing existing .venv\n' >> "$LOG_FILE"
  pass
fi

# shellcheck disable=SC1091
if ! source .venv/bin/activate; then
  printf '[5/%s] %-42s FAIL\n' "$TOTAL_STEPS" 'Python requirements'
  show_failure_tail 'Unable to activate the Python virtual environment.'
  exit 1
fi

step 5 'Python requirements'
log_section 'Python requirements'
if run_logged python3 -m pip install --upgrade pip && run_logged python3 -m pip install -r requirements.txt; then pass; else fail; show_failure_tail 'Unable to install Python requirements.'; exit 1; fi

CORE_COUNT=${#CORE_PACKAGES[@]}; AVAILABLE_COUNT=${#AVAILABLE_EXTRA[@]}; FAILED_COUNT=${#FAILED_EXTRA[@]}
OPTIONAL_INSTALLED=$((AVAILABLE_COUNT - FAILED_COUNT)); OPTIONAL_TOTAL=${#EXTRA_PACKAGES[@]}
PYTHON_REQUIREMENT_COUNT="$(awk 'NF && $1 !~ /^#/ {count++} END {print count+0}' requirements.txt)"
printf '\nSummary\n-------\n'
printf 'Required packages:       %s/%s\n' "$CORE_COUNT" "$CORE_COUNT"
printf 'Recommended/optional:    %s/%s\n' "$OPTIONAL_INSTALLED" "$OPTIONAL_TOTAL"
printf 'Python requirements:     %s installed\n' "$PYTHON_REQUIREMENT_COUNT"
REDUCED=0
if ((${#UNAVAILABLE_EXTRA[@]} || ${#FAILED_EXTRA[@]} || APT_FILE_WARNING)); then REDUCED=1; fi
if ((REDUCED)); then printf 'Setup status:            READY WITH REDUCED COVERAGE\n'; else printf 'Setup status:            READY\n'; fi
if ((${#UNAVAILABLE_EXTRA[@]} || ${#FAILED_EXTRA[@]})); then
  printf 'Missing optional:\n'
  for package in "${UNAVAILABLE_EXTRA[@]}" "${FAILED_EXTRA[@]}"; do [[ -n "$package" ]] && printf '  - %s\n' "$package"; done
fi

printf '\nEnvironment Readiness\n=====================\n'
readiness_line() { printf '%-27s %s\n' "$1" "$2"; }
if [[ -r /etc/os-release ]] && grep -qi 'ubuntu' /etc/os-release; then readiness_line 'Operating System' 'PASS'; else readiness_line 'Operating System' 'WARN'; REDUCED=1; fi
if [[ -n "${VIRTUAL_ENV:-}" ]] && [[ -x "${VIRTUAL_ENV}/bin/python" ]]; then readiness_line 'Python Environment' 'PASS'; else readiness_line 'Python Environment' 'WARN'; REDUCED=1; fi
REQ_CMDS=(python3 file readelf ss dpkg dpkg-deb)
missing_required=()
for cmd in "${REQ_CMDS[@]}"; do command -v "$cmd" >/dev/null 2>&1 || missing_required+=("$cmd"); done
if ((${#missing_required[@]})); then readiness_line 'Required Commands' 'FAIL'; else readiness_line 'Required Commands' 'PASS'; fi
if command -v getfacl >/dev/null 2>&1 && command -v setfacl >/dev/null 2>&1; then readiness_line 'ACL Analysis' 'PASS'; else readiness_line 'ACL Analysis' 'WARN'; REDUCED=1; fi
if command -v readelf >/dev/null 2>&1 && command -v checksec >/dev/null 2>&1; then readiness_line 'ELF Analysis' 'PASS'; else readiness_line 'ELF Analysis' 'WARN'; REDUCED=1; fi
if command -v ss >/dev/null 2>&1 && command -v tcpdump >/dev/null 2>&1; then readiness_line 'Network Analysis' 'PASS'; else readiness_line 'Network Analysis' 'WARN'; REDUCED=1; fi
if command -v ps >/dev/null 2>&1 && command -v lsof >/dev/null 2>&1 && command -v inotifywait >/dev/null 2>&1; then readiness_line 'Runtime Observation' 'PASS'; else readiness_line 'Runtime Observation' 'WARN'; REDUCED=1; fi
if command -v busctl >/dev/null 2>&1 && command -v gdbus >/dev/null 2>&1; then readiness_line 'D-Bus Analysis' 'PASS'; else readiness_line 'D-Bus Analysis' 'WARN'; REDUCED=1; fi
if ((${#missing_required[@]})); then
  printf '\nUbuntuClientAssess:       FAILED\n'
  printf 'Missing required commands:'; printf ' %s' "${missing_required[@]}"; printf '\n'
  exit 1
elif ((REDUCED)); then
  printf '\nUbuntuClientAssess:       READY WITH REDUCED COVERAGE\n'
else
  printf '\nUbuntuClientAssess:       READY\n'
fi

printf '\nDetailed installation log:\n  %s\n' "$LOG_FILE"
printf '\nActivate the environment with:\n  source .venv/bin/activate\n'
