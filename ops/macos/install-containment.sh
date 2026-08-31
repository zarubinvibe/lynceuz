#!/bin/sh
set -eu

USER_NAME=_lynceuz
GROUP_NAME=_lynceuz
LYNCEUZ_UID=401
LYNCEUZ_GID=401
ANCHOR_NAME=com.lynceuz/browser
ANCHOR_TARGET=/etc/pf.anchors/com.lynceuz.browser
PF_CONF=/etc/pf.conf
PLIST_TARGET=/Library/LaunchDaemons/com.lynceuz.browser-containment.plist
SUDOERS_TARGET=/etc/sudoers.d/lynceuz-browser
LABEL=com.lynceuz.browser-containment
PF_BEGIN='# BEGIN LYNCEUZ BROWSER CONTAINMENT'
PF_END='# END LYNCEUZ BROWSER CONTAINMENT'

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
ANCHOR_SOURCE=$SCRIPT_DIR/pf/lynceuz-browser.anchor.conf.in
PLIST_SOURCE=$SCRIPT_DIR/launchd/com.lynceuz.browser-containment.plist
SUDOERS_SOURCE=$SCRIPT_DIR/sudoers/lynceuz-browser
TEMP_DIR=

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  case ${TEMP_DIR:-} in
    /private/tmp/lynceuz-containment.*) /bin/rm -rf -- "$TEMP_DIR" ;;
  esac
}
trap cleanup EXIT HUP INT TERM

usage() {
  printf '%s\n' \
    'Usage: install-containment.sh [--dry-run|--apply|--rollback]' \
    'Default: --dry-run. Only the owner runs --apply/--rollback as root.'
}

show_plan() {
  printf '%s\n' \
    "mode: $1" \
    "identity: $USER_NAME uid=$LYNCEUZ_UID gid=$LYNCEUZ_GID" \
    "PF anchor: $ANCHOR_NAME <- $ANCHOR_TARGET" \
    "PF attachment: $PF_CONF" \
    "launchd: $PLIST_TARGET" \
    "sudoers: $SUDOERS_TARGET" \
    "rollback: $0 --rollback"
}

require_root() {
  [ "$(/usr/bin/id -u)" -eq 0 ] || die "$1 requires an existing root shell"
}

require_regular() {
  [ -f "$1" ] && [ ! -L "$1" ] || die "required regular file missing: $1"
}

reject_target_symlink() {
  [ ! -L "$1" ] || die "refusing symlink target: $1"
}

resolve_owner() {
  # The sudoers right must follow the actual owner, never root and never a name
  # baked into the repository. Prefer the SUDO_USER the elevated shell carries;
  # in a bare root shell fall back to the console login, then to $USER.
  candidate=${SUDO_USER:-}
  [ -n "$candidate" ] || candidate=$(/usr/bin/logname 2>/dev/null || :)
  [ -n "$candidate" ] || candidate=${USER:-}
  case $candidate in
    ''|root) die 'cannot resolve the owner login; run --apply so SUDO_USER or the console login is set' ;;
    *[!A-Za-z0-9._-]*) die 'refusing owner login with unexpected characters' ;;
  esac
  printf '%s' "$candidate"
}

read_attribute() {
  /usr/bin/dscl . -read "$1" "$2" 2>/dev/null |
    /usr/bin/awk -v key="$2:" '$1 == key { print $2; exit }'
}

pf_block() {
  printf '%s\n' \
    "$PF_BEGIN" \
    'anchor "com.lynceuz/browser"' \
    'load anchor "com.lynceuz/browser" from "/etc/pf.anchors/com.lynceuz.browser"' \
    "$PF_END"
}

validate_sources() {
  require_regular "$ANCHOR_SOURCE"
  require_regular "$PLIST_SOURCE"
  require_regular "$SUDOERS_SOURCE"
  [ "$(/usr/bin/awk '{ n += gsub(/__LYNCEUZ_UID__/, "&") } END { print n + 0 }' "$ANCHOR_SOURCE")" -eq 3 ] ||
    die 'PF template must contain only the three UID substitutions'
  /usr/bin/plutil -lint "$PLIST_SOURCE" >/dev/null
  /usr/sbin/visudo -cf "$SUDOERS_SOURCE" >/dev/null
}

ensure_identity() {
  if /usr/bin/dscl . -read "/Groups/$GROUP_NAME" >/dev/null 2>&1; then
    [ "$(read_attribute "/Groups/$GROUP_NAME" PrimaryGroupID)" = "$LYNCEUZ_GID" ] ||
      die "$GROUP_NAME exists with another GID"
  else
    [ -z "$(/usr/bin/dscl . -search /Groups PrimaryGroupID "$LYNCEUZ_GID" 2>/dev/null || :)" ] ||
      die "GID $LYNCEUZ_GID is already allocated"
    /usr/bin/dscl . -create "/Groups/$GROUP_NAME"
    /usr/bin/dscl . -create "/Groups/$GROUP_NAME" PrimaryGroupID "$LYNCEUZ_GID"
    /usr/bin/dscl . -create "/Groups/$GROUP_NAME" RealName 'Lynceuz browser containment'
    /usr/bin/dscl . -create "/Groups/$GROUP_NAME" Password '*'
  fi

  if /usr/bin/dscl . -read "/Users/$USER_NAME" >/dev/null 2>&1; then
    [ "$(read_attribute "/Users/$USER_NAME" UniqueID)" = "$LYNCEUZ_UID" ] ||
      die "$USER_NAME exists with another UID"
    [ "$(read_attribute "/Users/$USER_NAME" PrimaryGroupID)" = "$LYNCEUZ_GID" ] ||
      die "$USER_NAME exists with another primary GID"
  else
    [ -z "$(/usr/bin/dscl . -search /Users UniqueID "$LYNCEUZ_UID" 2>/dev/null || :)" ] ||
      die "UID $LYNCEUZ_UID is already allocated"
    /usr/bin/dscl . -create "/Users/$USER_NAME"
    /usr/bin/dscl . -create "/Users/$USER_NAME" UniqueID "$LYNCEUZ_UID"
    /usr/bin/dscl . -create "/Users/$USER_NAME" PrimaryGroupID "$LYNCEUZ_GID"
    /usr/bin/dscl . -create "/Users/$USER_NAME" RealName 'Lynceuz contained browser'
    /usr/bin/dscl . -create "/Users/$USER_NAME" NFSHomeDirectory /var/empty
    /usr/bin/dscl . -create "/Users/$USER_NAME" UserShell /usr/bin/false
    /usr/bin/dscl . -create "/Users/$USER_NAME" IsHidden 1
    /usr/bin/dscl . -create "/Users/$USER_NAME" Password '*'
  fi
}

install_pf_attachment() {
  if /usr/bin/grep -Fqx "$PF_BEGIN" "$PF_CONF"; then
    actual=$(/usr/bin/sed -n "/^$PF_BEGIN$/,/^$PF_END$/p" "$PF_CONF")
    [ "$actual" = "$(pf_block)" ] || die 'existing Lynceuz PF block differs; rollback it first'
    return
  fi
  ! /usr/bin/grep -Fqx "$PF_END" "$PF_CONF" || die 'orphaned Lynceuz PF end marker'
  { /bin/cat "$PF_CONF"; printf '\n'; pf_block; } >"$TEMP_DIR/pf.conf"
  /sbin/pfctl -n -f "$TEMP_DIR/pf.conf" >/dev/null
  /usr/bin/install -o root -g wheel -m 0644 "$TEMP_DIR/pf.conf" "$PF_CONF"
}

remove_pf_attachment() {
  /usr/bin/grep -Fqx "$PF_BEGIN" "$PF_CONF" || return
  actual=$(/usr/bin/sed -n "/^$PF_BEGIN$/,/^$PF_END$/p" "$PF_CONF")
  [ "$actual" = "$(pf_block)" ] || die 'refusing to remove a modified Lynceuz PF block'
  /usr/bin/awk -v begin="$PF_BEGIN" -v end="$PF_END" '
    $0 == begin { inside = 1; next }
    $0 == end { inside = 0; next }
    !inside { print }
    END { if (inside) exit 2 }
  ' "$PF_CONF" >"$TEMP_DIR/pf.conf"
  /sbin/pfctl -n -f "$TEMP_DIR/pf.conf" >/dev/null
  /usr/bin/install -o root -g wheel -m 0644 "$TEMP_DIR/pf.conf" "$PF_CONF"
}

apply() {
  require_root --apply
  validate_sources
  for target in "$ANCHOR_TARGET" "$PF_CONF" "$PLIST_TARGET" "$SUDOERS_TARGET"; do
    reject_target_symlink "$target"
  done
  TEMP_DIR=$(/usr/bin/mktemp -d /private/tmp/lynceuz-containment.XXXXXX)
  ensure_identity
  /usr/bin/sed "s/__LYNCEUZ_UID__/$LYNCEUZ_UID/g" "$ANCHOR_SOURCE" >"$TEMP_DIR/anchor"
  ! /usr/bin/grep -q '__LYNCEUZ_UID__' "$TEMP_DIR/anchor" || die 'UID substitution failed'
  /sbin/pfctl -n -a "$ANCHOR_NAME" -f "$TEMP_DIR/anchor" >/dev/null
  owner=$(resolve_owner)
  /usr/bin/sed "s/__LYNCEUZ_OWNER__/$owner/g" "$SUDOERS_SOURCE" >"$TEMP_DIR/sudoers"
  ! /usr/bin/grep -q '__LYNCEUZ_OWNER__' "$TEMP_DIR/sudoers" || die 'owner substitution failed'
  /usr/sbin/visudo -cf "$TEMP_DIR/sudoers" >/dev/null
  /usr/bin/install -o root -g wheel -m 0644 "$TEMP_DIR/anchor" "$ANCHOR_TARGET"
  /usr/bin/install -o root -g wheel -m 0644 "$PLIST_SOURCE" "$PLIST_TARGET"
  /usr/bin/install -o root -g wheel -m 0440 "$TEMP_DIR/sudoers" "$SUDOERS_TARGET"
  install_pf_attachment
  if /bin/launchctl print "system/$LABEL" >/dev/null 2>&1; then
    /bin/launchctl bootout "system/$LABEL"
  fi
  /bin/launchctl bootstrap system "$PLIST_TARGET"
  printf 'sudoers PF-read and contained-node rights granted to owner: %s\n' "$owner"
  printf '%s\n' 'Applied repository templates. Reboot, then run the separate containment canary.'
}

rollback() {
  require_root --rollback
  for target in "$ANCHOR_TARGET" "$PF_CONF" "$PLIST_TARGET" "$SUDOERS_TARGET"; do
    reject_target_symlink "$target"
  done
  TEMP_DIR=$(/usr/bin/mktemp -d /private/tmp/lynceuz-containment.XXXXXX)
  if /bin/launchctl print "system/$LABEL" >/dev/null 2>&1; then
    /bin/launchctl bootout "system/$LABEL"
  fi
  if [ -e "$ANCHOR_TARGET" ]; then
    /sbin/pfctl -a "$ANCHOR_NAME" -F all
  fi
  remove_pf_attachment
  /bin/rm -f -- "$PLIST_TARGET" "$SUDOERS_TARGET" "$ANCHOR_TARGET"
  if /usr/bin/dscl . -read "/Users/$USER_NAME" >/dev/null 2>&1; then
    [ "$(read_attribute "/Users/$USER_NAME" UniqueID)" = "$LYNCEUZ_UID" ] || die 'refusing to delete mismatched user'
    /usr/bin/dscl . -delete "/Users/$USER_NAME"
  fi
  if /usr/bin/dscl . -read "/Groups/$GROUP_NAME" >/dev/null 2>&1; then
    [ "$(read_attribute "/Groups/$GROUP_NAME" PrimaryGroupID)" = "$LYNCEUZ_GID" ] || die 'refusing to delete mismatched group'
    /usr/bin/dscl . -delete "/Groups/$GROUP_NAME"
  fi
  # ponytail: shared PF stays enabled; reboot clears this job's enable reference without risking other macOS PF users.
  printf '%s\n' 'Rolled back Lynceuz files, identity and anchor rules. Reboot to clear the boot-scoped PF reference.'
}

mode=${1:---dry-run}
[ "$#" -le 1 ] || { usage >&2; exit 2; }
case $mode in
  --dry-run) show_plan dry-run ;;
  --apply) show_plan apply; apply ;;
  --rollback) show_plan rollback; rollback ;;
  -h|--help) usage ;;
  *) usage >&2; exit 2 ;;
esac
