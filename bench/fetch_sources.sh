#!/usr/bin/env bash
# Clone the public datasets the benchmark is built from (nothing is redistributed
# in this repo). Usage: bash bench/fetch_sources.sh [target_dir]
set -euo pipefail
DEST="${1:-bench/sources}"
mkdir -p "$DEST"
cd "$DEST"
clone() { [ -d "$(basename "$1")" ] || git clone --depth 1 "https://github.com/$1.git"; }
clone microsoft/BIPIA                    # MIT  - indirect injection benchmark (attacks + email/table contexts)
clone uiuc-kang-lab/InjecAgent           # MIT  - tool-output injection cases
clone ethz-spylab/agentdojo              # MIT  - agent injection goals + attack templates
clone HumanCompatibleAI/tensor-trust-data  # BSD-2 - human-written hijacking/extraction attacks
clone mozilla/readability                # Apache-2.0 - 130 real-world web pages (benign HTML)
echo "Sources ready in $DEST"