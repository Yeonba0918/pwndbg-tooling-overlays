#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 /path/to/pwndbg"
    exit 1
fi

target="$(realpath "$1")"
repo_root="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P)"
overlay_root="$repo_root/overlay"

if [[ ! -d "$target" ]]; then
    echo "Target checkout not found: $target"
    exit 1
fi

if [[ ! -d "$overlay_root" ]]; then
    echo "Overlay directory not found: $overlay_root"
    exit 1
fi

rsync -a "$overlay_root"/ "$target"/
echo "Applied overlay into: $target"
