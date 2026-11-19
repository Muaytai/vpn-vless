#!/bin/sh
set -eu
umask 077

fail() { printf '%s\n' "install: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail 'run explicitly as root'
[ "$(uname -s)" = Linux ] || fail 'Linux is required'
[ -r /etc/os-release ] || fail 'cannot identify the operating system'
# shellcheck disable=SC1091
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
    *' debian '*|*' ubuntu '*) ;;
    *) fail 'Debian or Ubuntu is required' ;;
esac
command -v systemctl >/dev/null 2>&1 || fail 'systemd is required'
[ -d /run/systemd/system ] || fail 'systemd must be running'
command -v go >/dev/null 2>&1 || fail 'Go 1.26 or newer is required'
version=$(GOTOOLCHAIN=local go version) || fail 'cannot determine local Go version'
version=${version#go version go}
version=${version%% *}
case "$version" in
    1.*) minor=${version#1.}; minor=${minor%%[!0-9]*}; case "$minor" in ''|*[!0-9]*) fail 'Go 1.26 or newer is required';; esac
         [ "$minor" -ge 26 ] || fail 'Go 1.26 or newer is required' ;;
    [2-9].*|[1-9][0-9].*) ;;
    *) fail 'Go 1.26 or newer is required' ;;
esac

# Run from the project root; reject existing targets instead of guessing ownership.
[ -f ./go.mod ] && [ -d ./cmd/vpnctl ] && [ -f ./deploy/vpn-vless.service ] || fail 'run from the vpn-vless project root'
for target in /usr/local/bin/xray /usr/local/bin/vpnctl /etc/systemd/system/vpn-vless.service /usr/lib/systemd/system/vpn-vless.service /lib/systemd/system/vpn-vless.service /etc/vpn-vless /var/lib/vpn-vless; do
    [ ! -e "$target" ] && [ ! -L "$target" ] || fail "target already exists: $target"
done
if getent passwd vpn-vless >/dev/null; then fail 'user vpn-vless already exists'; fi
if getent group vpn-vless >/dev/null; then fail 'group vpn-vless already exists'; fi
units=$(systemctl list-unit-files --no-legend 'vpn-vless.service') || fail 'cannot inspect existing systemd units'
if printf '%s\n' "$units" | grep -q 'vpn-vless.service'; then
    fail 'unit vpn-vless.service already exists'
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/vpn-vless-install.XXXXXXXX") || fail 'cannot create temporary directory'
group_created=0
user_created=0
group_identity=
user_identity=
config_created=0
state_created=0
config_identity=
state_identity=
xray_pending=0
vpnctl_pending=0
unit_pending=0
enable_attempted=0
committed=0
temporary=
xray_reference=
vpnctl_reference=
unit_reference=

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    set +e
    cleanup_failed=0
    if [ "$committed" -eq 0 ]; then
        # disable may be needed even when enable returned an error: systemd can
        # create links before reporting failure. Only disable our own unit.
        if [ "$unit_pending" -eq 1 ] && [ "$enable_attempted" -eq 1 ]; then
            if [ -n "$unit_reference" ] && [ /etc/systemd/system/vpn-vless.service -ef "$unit_reference" ]; then
                systemctl disable vpn-vless.service || { printf '%s\n' 'install: rollback failed: systemctl disable vpn-vless.service' >&2; cleanup_failed=1; }
            else
                printf '%s\n' 'install: rollback skipped disable: unit is no longer ours' >&2
                cleanup_failed=1
            fi
        fi
        for item in unit vpnctl xray; do
            case "$item" in
                unit) created=$unit_pending; target=/etc/systemd/system/vpn-vless.service; source=$unit_reference ;;
                vpnctl) created=$vpnctl_pending; target=/usr/local/bin/vpnctl; source=$vpnctl_reference ;;
                xray) created=$xray_pending; target=/usr/local/bin/xray; source=$xray_reference ;;
            esac
            if [ "$created" -eq 1 ] && { [ -e "$target" ] || [ -L "$target" ]; }; then
                if [ "$target" -ef "$source" ]; then
                    rm -f -- "$target" || { printf '%s\n' "install: rollback failed: remove $target" >&2; cleanup_failed=1; }
                else
                    printf '%s\n' "install: rollback skipped replaced target: $target" >&2
                    cleanup_failed=1
                fi
            fi
        done
        if [ "$unit_pending" -eq 1 ]; then
            systemctl daemon-reload || { printf '%s\n' 'install: rollback failed: systemctl daemon-reload' >&2; cleanup_failed=1; }
        fi
        for item in state config; do
            case "$item" in
                state) created=$state_created; target=/var/lib/vpn-vless ;;
                config) created=$config_created; target=/etc/vpn-vless ;;
            esac
            if [ "$created" -eq 1 ] && { [ -e "$target" ] || [ -L "$target" ]; }; then
                identity=$(stat -Lc '%d:%i' -- "$target") || identity=
                case "$item" in state) expected=$state_identity ;; config) expected=$config_identity ;; esac
                if [ -n "$expected" ] && [ "$identity" = "$expected" ] && [ -d "$target" ] && [ ! -L "$target" ]; then
                    rmdir -- "$target" || { printf '%s\n' "install: rollback failed: remove $target (not empty or inaccessible)" >&2; cleanup_failed=1; }
                else
                    printf '%s\n' "install: rollback skipped replaced or unverified directory: $target" >&2
                    cleanup_failed=1
                fi
            fi
        done
        if [ "$user_created" -eq 1 ]; then
            current=$(getent passwd vpn-vless) || current=
            if [ -n "$user_identity" ] && [ "$current" = "$user_identity" ]; then
                userdel vpn-vless || { printf '%s\n' 'install: rollback failed: userdel vpn-vless' >&2; cleanup_failed=1; }
            else
                printf '%s\n' 'install: rollback skipped replaced or unverified user vpn-vless' >&2
                cleanup_failed=1
            fi
        fi
        if [ "$group_created" -eq 1 ]; then
            current=$(getent group vpn-vless) || current=
            if [ -n "$group_identity" ] && [ "$current" = "$group_identity" ]; then
                groupdel vpn-vless || { printf '%s\n' 'install: rollback failed: groupdel vpn-vless' >&2; cleanup_failed=1; }
            else
                printf '%s\n' 'install: rollback skipped replaced or unverified group vpn-vless' >&2
                cleanup_failed=1
            fi
        fi
    fi
    if [ -n "$temporary" ]; then
        case "$temporary" in "$unit_reference"|"$vpnctl_reference"|"$xray_reference") temporary= ;; esac
    fi
    for ref in "$temporary" "$unit_reference" "$vpnctl_reference" "$xray_reference"; do
        if [ -n "$ref" ]; then
            rm -f -- "$ref" || { printf '%s\n' "install: cleanup failed: remove $ref" >&2; cleanup_failed=1; }
        fi
    done
    rm -rf -- "$work" || { printf '%s\n' "install: cleanup failed: remove $work" >&2; cleanup_failed=1; }
    [ "$cleanup_failed" -eq 0 ] || status=1
    exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
mkdir "$work/bin"
# Prevent automatic downloads of a different Go toolchain.
GOTOOLCHAIN=local GOBIN="$work/bin" go install github.com/xtls/xray-core/main@v1.260327.0
GOTOOLCHAIN=local go build -o "$work/bin/vpnctl" -buildvcs=false ./cmd/vpnctl
[ -f "$work/bin/main" ] || fail 'Xray build did not produce the expected binary'
[ -f "$work/bin/vpnctl" ] || fail 'vpnctl build did not produce the expected binary'

# Refuse to overwrite even if a target appeared during the builds.
for target in /usr/local/bin/xray /usr/local/bin/vpnctl /etc/systemd/system/vpn-vless.service /etc/vpn-vless /var/lib/vpn-vless; do
    [ ! -e "$target" ] && [ ! -L "$target" ] || fail "target appeared during build: $target"
done
groupadd --system vpn-vless
group_created=1
group_identity=$(getent group vpn-vless) || fail 'cannot identify created group'
useradd --system --gid vpn-vless --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin vpn-vless
user_created=1
user_identity=$(getent passwd vpn-vless) || fail 'cannot identify created user'
mkdir -m 0700 /etc/vpn-vless || fail 'cannot create /etc/vpn-vless without overwriting an existing directory'
config_created=1
config_identity=$(stat -Lc '%d:%i' -- /etc/vpn-vless) || fail 'cannot identify /etc/vpn-vless'
chown root:vpn-vless /etc/vpn-vless
chmod 0750 /etc/vpn-vless
mkdir -m 0700 /var/lib/vpn-vless || fail 'cannot create /var/lib/vpn-vless without overwriting an existing directory'
state_created=1
state_identity=$(stat -Lc '%d:%i' -- /var/lib/vpn-vless) || fail 'cannot identify /var/lib/vpn-vless'
chown root:root /var/lib/vpn-vless
# Link prepared files into place atomically; ln never replaces an existing target.
install -o root -g root -m 0755 "$work/bin/main" "$work/xray"
install -o root -g root -m 0755 "$work/bin/vpnctl" "$work/vpnctl"
install -o root -g root -m 0644 ./deploy/vpn-vless.service "$work/vpn-vless.service"
install_no_overwrite() {
    source=$1
    target=$2
    # Each temporary file is on the destination filesystem and named by mktemp.
    temporary=$(mktemp "${target}.install.XXXXXXXX") || fail "cannot create temporary file for $target"
    if ! install -o root -g root -m "$3" "$source" "$temporary"; then
        fail "cannot prepare $target"
    fi
    # Keep the destination-filesystem inode reference until cleanup.
    case "$4" in
        xray) xray_reference=$temporary ;;
        vpnctl) vpnctl_reference=$temporary ;;
        unit) unit_reference=$temporary ;;
    esac
    temporary=
    case "$4" in
        xray) xray_pending=1 ;;
        vpnctl) vpnctl_pending=1 ;;
        unit) unit_pending=1 ;;
    esac
    case "$4" in
        xray) ref=$xray_reference ;;
        vpnctl) ref=$vpnctl_reference ;;
        unit) ref=$unit_reference ;;
    esac
    if ! ln -T "$ref" "$target"; then
        case "$4" in
            xray) xray_pending=0 ;;
            vpnctl) vpnctl_pending=0 ;;
            unit) unit_pending=0 ;;
        esac
        fail "cannot install $target without overwriting an existing target"
    fi
}
install_no_overwrite "$work/xray" /usr/local/bin/xray 0755 xray
install_no_overwrite "$work/vpnctl" /usr/local/bin/vpnctl 0755 vpnctl
install_no_overwrite "$work/vpn-vless.service" /etc/systemd/system/vpn-vless.service 0644 unit
systemctl daemon-reload
enable_attempted=1
systemctl enable vpn-vless.service
committed=1
printf '%s\n' 'Installed and enabled vpn-vless; service was not started. Apply a configuration first.'
