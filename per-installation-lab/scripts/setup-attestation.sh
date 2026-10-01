#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# Dependência oficial pré-1.0: versão auditável, sem acompanhar main implicitamente.
revision=55c35040a1b5b72e6d63bfb150c5c68a175c1462
source_dir="$repo_dir/.local/keyattestation"
mkdir -p "$repo_dir/.local"
if [[ ! -d "$source_dir/.git" ]]; then
    git init "$source_dir"
    git -C "$source_dir" remote add origin https://github.com/android/keyattestation.git
fi
if ! git -C "$source_dir" cat-file -e "$revision^{commit}" 2>/dev/null; then
    git -C "$source_dir" fetch --depth 1 origin "$revision"
fi
git -C "$source_dir" checkout --detach "$revision"
if [[ -n "$(git -C "$source_dir" status --porcelain -- . ':!build' ':!.gradle' ':!.kotlin')" ]]; then
    printf 'O verificador oficial tem alterações locais; examine antes de compilar.\n' >&2
    exit 1
fi
"$repo_dir/android/gradlew" -p "$repo_dir/server/attestation-verifier" \
    --no-daemon --max-workers=2 installDist
