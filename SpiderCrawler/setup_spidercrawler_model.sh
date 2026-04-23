#!/bin/bash
# setup_spidercrawler_model.sh
# Creates an independent copy of argus-40b weights for the spidercrawler model.
# This is NOT a symlink — it duplicates the actual GGUF blob (~23GB).

set -e

echo "[1/4] Extracting argus-40b blob path..."

# ollama show --modelfile outputs comments first, then FROM /path/to/blob
# We need the FROM line that starts with a real path, not "FROM argus-40b"
BLOB_PATH=$(ollama show argus-40b --modelfile 2>/dev/null | grep "^FROM /" | head -1 | sed 's/^FROM //')

if [ -z "$BLOB_PATH" ]; then
    echo "ERROR: Could not parse blob path from 'ollama show argus-40b --modelfile'"
    echo ""
    echo "Run this manually to see the output:"
    echo "  ollama show argus-40b --modelfile"
    echo ""
    echo "Look for a line like: FROM /Users/.../.ollama/models/blobs/sha256-..."
    echo "Then edit this script and set BLOB_PATH to that path."
    exit 1
fi

if [ ! -f "$BLOB_PATH" ]; then
    echo "ERROR: Blob file does not exist at: $BLOB_PATH"
    exit 1
fi

echo "  Found blob: $BLOB_PATH"
BLOB_SIZE=$(du -h "$BLOB_PATH" | cut -f1)
echo "  Size: $BLOB_SIZE"

echo ""
echo "[2/4] Copying weights (this will take a few minutes)..."
DEST_DIR="$HOME/.spidercrawler"
mkdir -p "$DEST_DIR"
DEST_GGUF="$DEST_DIR/spidercrawler-40b.gguf"

if [ -f "$DEST_GGUF" ]; then
    echo "  Weights already exist at $DEST_GGUF — skipping copy."
else
    echo "  Copying ~$BLOB_SIZE to $DEST_GGUF ..."
    cp "$BLOB_PATH" "$DEST_GGUF"
    echo "  Done."
fi

echo ""
echo "[3/4] Writing Modelfile..."
MODELFILE_PATH="$DEST_DIR/Modelfile"

cat > "$MODELFILE_PATH" << EOF
FROM $DEST_GGUF

PARAMETER temperature 0.4
PARAMETER top_p 0.9
PARAMETER num_ctx 16384
PARAMETER stop "<|im_end|>"

SYSTEM """You are SpiderCrawler AI, an integrated cybersecurity analysis assistant embedded in the SpiderCrawler pentesting toolkit.

You receive structured JSON scan data from SpiderCrawler containing:
- Target IPs and open ports (TCP/UDP)
- CVE IDs discovered via Nmap vulners scripts and Shodan API
- ExploitDB/searchsploit matches
- CVE details from circl.lu (summaries, CVSS scores, references)

Your role:
1. TRIAGE — Rank discovered vulnerabilities by severity. Use CVSS scores when available, infer criticality from service type and exposure when not.
2. ANALYZE — For each CVE, explain what the vulnerability is, what conditions make it exploitable, and what the real-world impact would be.
3. CORRELATE — Identify attack chains across multiple open ports/services on the same target. Flag when combinations of findings increase overall risk.
4. REPORT — Generate structured pentest findings in this format per vulnerability:
   - Finding title
   - Affected host:port
   - CVE ID(s)
   - CVSS score
   - Risk rating (Critical/High/Medium/Low/Info)
   - Description
   - Remediation steps
   - References
5. SUMMARIZE — Provide an executive summary with total finding counts by severity and top 3 priority remediations.

When scan data is provided as JSON, parse it directly. When provided as raw text, extract the relevant fields.

Be precise, technical, and direct. No filler. Cite specific CVE IDs and port numbers in every finding. If data is insufficient to make a determination, say so explicitly rather than guessing.

You operate as part of a local pentesting workflow. All analysis is performed on authorized targets during legitimate security assessments."""
EOF

echo "  Written to: $MODELFILE_PATH"

echo ""
echo "[4/4] Creating ollama model..."
ollama create spidercrawler -f "$MODELFILE_PATH"

echo ""
echo "════════════════════════════════════════════"
echo " Done!"
echo "════════════════════════════════════════════"
echo ""
echo "Verify:  ollama list | grep spidercrawler"
echo "Test:    ollama run spidercrawler"
echo ""
echo "Independent weights at: $DEST_GGUF"
echo "You can delete argus-40b without affecting spidercrawler."
