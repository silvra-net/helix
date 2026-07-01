#!/usr/bin/env bash
# Helix Dev-Loop — alle 4h via Cron (0 5,9,13,17,21 * * *)
# Pro Session: so viele Node + Spark-Client-Aufgaben wie möglich + Nightly Build
# KEIN Self-Restart — der Cron-Eintrag ist der einzige Taktgeber.

LOCKFILE="/tmp/helix-claude-lock"
LOGFILE="/tmp/helix-cron-4h.log"
CLAUDE="/home/vistos/.local/bin/claude"
PROJECT="/home/vistos/projects/helix"
SPARK_PROJECT="/home/vistos/projects/spark"
STATE_FILE="$PROJECT/.claude-session-state.md"
BUILD_DIR="$PROJECT/builds"
NOTIFY="/home/vistos/projects/spark/scripts/claude-notify.js"
SESSION_START=$(date -u '+%Y-%m-%d %H:%M UTC')
IS_NIGHTLY=false

# Nightly: erste Session des Tages (05:xx Berliner Zeit)
HOUR=$(date '+%H')
[ "$HOUR" = "05" ] && IS_NIGHTLY=true

notify() {
  node "$NOTIFY" "$1" 2>/dev/null \
    && echo "$(date '+%H:%M') Notification gesendet: $1" \
    || echo "$(date '+%H:%M') Notification fehlgeschlagen"
}

# Log-Rotation
if [ -f "$LOGFILE" ] && [ "$(wc -l < "$LOGFILE" 2>/dev/null)" -gt 1200 ]; then
  tail -1000 "$LOGFILE" > "${LOGFILE}.tmp" && mv "${LOGFILE}.tmp" "$LOGFILE"
fi
exec >> "$LOGFILE" 2>&1
echo ""
echo "=== $SESSION_START === Helix Dev-Session startet (nightly=$IS_NIGHTLY) ==="

# Lock — verhindert Überschneidungen
if [ -f "$LOCKFILE" ]; then
  PID=$(cat "$LOCKFILE" 2>/dev/null)
  if kill -0 "$PID" 2>/dev/null; then
    echo "Claude läuft bereits (PID $PID) — Session überspringen"
    exit 0
  fi
  rm -f "$LOCKFILE"
fi
echo $$ > "$LOCKFILE"

NIGHTLY_TAG=""
[ "$IS_NIGHTLY" = "true" ] && NIGHTLY_TAG=" + Nightly Build"
notify "⛓ Helix Dev-Session startet$NIGHTLY_TAG ($(date '+%H:%M'))"

# Build-Verzeichnis für Nightly-Artefakte
mkdir -p "$BUILD_DIR"

# WIP-Marker schreiben (überlebt Abstürze)
cat > "$STATE_FILE" << EOF
# Helix Dev Session State — WIP
Letzte Session: $SESSION_START
## Status
UNTERBROCHEN — Session lief aber Abschluss wurde nicht erreicht.
Falls dieser Text bleibt: git diff HEAD prüfen.
EOF

# Vorherigen State lesen
PREV_STATE=$(python3 -c "
try:
    content = open('$STATE_FILE').read()
    if len(content) > 3000: content = content[:3000] + '\n... (gekürzt)'
    print(content)
except: print('Erste Session.')
" 2>/dev/null || echo "Erste Session.")

GIT_LOG=$(git -C "$PROJECT" log --oneline -5 2>/dev/null || echo "(kein git)")
GIT_DIFF=$(git -C "$PROJECT" diff --stat HEAD 2>/dev/null | tail -5 || echo "(sauber)")
CARGO_CHECK=$(source "$HOME/.cargo/env" && cd "$PROJECT" && cargo check 2>&1 | grep -E "^error|^warning|Finished" | tail -8)

SPARK_CLIENT_STATUS="Spark-Client: $(ls $SPARK_PROJECT/client/src/screens/ 2>/dev/null | wc -l) Screens vorhanden"

NIGHTLY_SECTION=""
if [ "$IS_NIGHTLY" = "true" ]; then
  NIGHTLY_SECTION="
══════════════════════════════════════════════════════════
 NIGHTLY BUILD (heute: $SESSION_START)
══════════════════════════════════════════════════════════

Da dies die 05:00-Session ist, führe NACH den regulären Aufgaben Nightly Builds durch:

NODE NIGHTLY BUILD:
  source ~/.cargo/env
  cd $PROJECT
  cargo build --release 2>&1 | tail -10
  Wenn erfolgreich:
    cp target/release/helix $BUILD_DIR/helix-nightly-\$(date +%Y%m%d)
    cp target/release/hlx   $BUILD_DIR/hlx-nightly-\$(date +%Y%m%d)
    ls -t $BUILD_DIR/helix-nightly-* 2>/dev/null | tail -n +8 | xargs rm -f
    ls -t $BUILD_DIR/hlx-nightly-*   2>/dev/null | tail -n +8 | xargs rm -f
    echo 'Node Nightly Build OK'
  Wenn Fehler: im State vermerken.
"
fi

PROMPT="Du bist CTO und alleiniger Entwickler des Helix-Projekts (HLX).
Helix ist eine quantensichere Layer-1-Blockchain (Rust).
Das Helix-Wallet ist IN die Spark-App integriert (kein separates helix-app Projekt mehr).
Du wirst alle 4h aktiviert. Pro Session erledigst du SO VIELE Aufgaben wie möglich:
  - Node-Aufgaben (Rust-Blockchain, Projekt: $PROJECT)
  - Spark-Client-Aufgaben (Helix-Integration: $SPARK_PROJECT/client/)
  Was angefangen wird, wird fertig. Kein halbfertiger Code. Dann sofort weiter.

SESSION: $SESSION_START
NODE-PROJEKT: $PROJECT
APP-PROJEKT:  $APP_PROJECT
RPC-URL:      https://helix.silvra.net  (Cloudflare Tunnel → localhost:8545)

══════════════════════════════════════════════════════════
 PRODUKT-VISION: HELIX (HLX)
══════════════════════════════════════════════════════════

NODE (Rust, Projekt: $PROJECT):
  - ML-DSA (Dilithium3) — NIST PQC Signaturen
  - BLAKE3 Hashing, PoS + BFT Konsensus, libp2p P2P
  - REST API auf :8545 (erreichbar als https://helix.silvra.net)
  - P2P auf :8546 (libp2p gossipsub + mDNS)

SPARK-CLIENT (Helix-Integration, Projekt: $SPARK_PROJECT/client/):
  ⚠️ KEIN separates helix-app Projekt. Das Helix-Wallet ist IN die Spark-App integriert.
  Spark ist ein React Native App (Expo bare workflow, Expo SDK 54).
  Wallet-Tab in der Spark-App (src/screens/ oder navigation/):
    - HLX-Keypair generieren + sicher speichern (Expo SecureStore)
    - Balance, Adresse (QR-Code), Senden/Empfangen
    - Block Explorer (Chain-Status, letzte Blöcke)
    - Verbindet sich mit https://helix.silvra.net
  Styles: Spark-Theme (theme.ts, #3D50E0 Blau — NICHT Helix-Dunkelthema)
  Expo-Pakete: IMMER npx expo install, NIEMALS npm install!

══════════════════════════════════════════════════════════
 NODE ROADMAP (Rust)
══════════════════════════════════════════════════════════

✅ Phase 1 — Foundation (ML-DSA, BLAKE3, Adressen, Block/Tx)
✅ Phase 2 — Living Chain (BFT Single-Validator, Mempool, REST API)
✅ Phase 3 — State Machine (Tx-Execution, Fee-Split, redb, hlx CLI)
✅ Phase 4 — Networking (libp2p gossipsub + mDNS, Wallet-Encryption)

🔄 Phase 5 — Multi-Validator BFT (AKTUELLE NODE-PHASE)
  [ ] Validator-Set-Rotation (Epochen, alle N Blöcke)
  [ ] Stake/Unstake wirkt sich auf ValidatorSet aus
  [ ] Slashing bei Double-Signing (DoubleSignEvidence → Stake-Abzug)
  [ ] P2P: Vote-Propagation zwischen Peers

📋 Phase 6 — Proof of Personhood & Identität
  Human-readable Names (alice.hlx), Personhood-Attestation, Social Recovery

📋 Phase 7 — Smart Contracts (WASM VM, Gas Metering)

📋 Phase 8 — Production Hardening (ML-KEM P2P, ZK-STARKs, Testnet)

══════════════════════════════════════════════════════════
 SPARK-CLIENT ROADMAP (Helix-Integration)
══════════════════════════════════════════════════════════

🔄 Phase SA1 — Wallet-Tab Grundstruktur (AKTUELLE CLIENT-PHASE)
  Datei: $SPARK_PROJECT/client/src/screens/WalletScreen.tsx (prüfen ob vorhanden)
  Navigation: in AppNavigator.tsx als Tab einbinden (Wallet zwischen Chats und Profil)
  [ ] WalletScreen mit Platzhalter anlegen falls nicht vorhanden
  [ ] Helix-API-Client: axios, Base URL https://helix.silvra.net, Types für NodeStatus/Block/Account
  [ ] /status Endpoint abfragen: Chain-Height, Best-Hash, Peers anzeigen
  [ ] Keypair generieren (noble-ed25519 als Platzhalter bis WASM-Binding fertig)
  [ ] Keypair in Expo SecureStore sichern (verschlüsselt)

📋 Phase SA2 — Balance + Transaktionen
  [ ] HLX-Balance: GET /accounts/:address
  [ ] Adresse als QR-Code anzeigen (expo-barcode-scanner oder react-native-qrcode-svg)
  [ ] Transfer-Screen: Empfänger-Adresse + Betrag → POST /transactions
  [ ] Tx-Status anzeigen

📋 Phase SA3 — Block Explorer
  [ ] Block-Liste (Polling alle 4s, neueste zuerst)
  [ ] Block-Detail (Txs, Validator, Hash, Zeit)
  [ ] Account-Lookup per Adresse

══════════════════════════════════════════════════════════
 LETZTER STATE & KONTEXT
══════════════════════════════════════════════════════════

LETZTER SESSION-STATE:
$PREV_STATE

GIT LOG NODE (letzte 5):
$GIT_LOG

GIT DIFF NODE (unstaged):
$GIT_DIFF

CARGO CHECK:
$CARGO_CHECK

APP-STATUS:
$APP_STATUS
$NIGHTLY_SECTION
══════════════════════════════════════════════════════════
 SCHRITT 1: ORIENTIERUNG (max. 4 Tool-Calls)
══════════════════════════════════════════════════════════

Prüfe:
  1. cargo check (falls oben Fehler) → höchste Priorität
  2. Ist $APP_PROJECT vorhanden? (ls -la $APP_PROJECT)
  3. Lies .claude-session-state.md
  4. git log --oneline -3

Falls cargo check Fehler → erst reparieren, dann App-Aufgabe.
Falls WIP im State → zuerst fertigstellen (zählt als eine der 2 Aufgaben).

══════════════════════════════════════════════════════════
 SCHRITT 2: NODE-AUFGABE (Rust-Blockchain)
══════════════════════════════════════════════════════════

Wähle die nächste offene Aufgabe aus Phase 5 (oder Phase 6 wenn 5 komplett).

Sofort nach Wahl: STATE_FILE aktualisieren mit \"Node-Aufgabe: [was]\".
Dann direkt implementieren.

Standards:
  - cargo check muss am Ende: 0 errors, 0 warnings
  - Keine eigene Kryptografie — nur NIST-Standards
  - Keine Breaking Changes an pub APIs ohne Not

══════════════════════════════════════════════════════════
 SCHRITT 3: SPARK-CLIENT-AUFGABE (Helix-Integration)
══════════════════════════════════════════════════════════

Arbeite im Spark-Client: $SPARK_PROJECT/client/
KEIN separates helix-app Projekt — das wurde abgeschafft.

Wähle die nächste offene Aufgabe aus Phase SA1 (oder SA2 wenn SA1 komplett).

WICHTIG — Spark-Client-Eigenheiten:
  - Expo bare workflow (NICHT managed), SDK 54
  - Pakete: IMMER npx expo install, NIEMALS npm install → sonst NoClassDefFoundError
  - Styles aus $SPARK_PROJECT/client/src/theme.ts (#3D50E0 Blau)
  - TypeScript strict — npx tsc --noEmit muss 0 Fehler zeigen
  - Error-, Loading-, Empty-States vollständig
  - Helix-API-Calls: Base URL https://helix.silvra.net (NICHT hardcoded, aus Config)

Prüfe zuerst: ls $SPARK_PROJECT/client/src/screens/ — gibt es schon einen WalletScreen?

══════════════════════════════════════════════════════════
 SCHRITT 4: ABSCHLUSS — NIEMALS ÜBERSPRINGEN
══════════════════════════════════════════════════════════

A) NODE — Qualitätssicherung:
    source ~/.cargo/env && cargo check
    → muss 0 errors, 0 warnings zeigen

B) NODE — Git Commit:
    git -C $PROJECT add [spezifische Dateien]
    git -C $PROJECT commit -m 'feat/fix/chore: ...'

C) SPARK-CLIENT — Qualitätssicherung:
    cd $SPARK_PROJECT/client && npx tsc --noEmit 2>&1 | tail -5

D) SPARK-CLIENT — Git Commit:
    git -C $SPARK_PROJECT add [spezifische client-Dateien]
    git -C $SPARK_PROJECT commit -m 'feat(wallet): ...'

E) README.md in $PROJECT aktualisieren:
    - [ ] → [x] für abgeschlossene Roadmap-Punkte

F) STATE-FILE abschließend schreiben ($STATE_FILE):

    # Helix Dev Session State
    Letzte Session: $SESSION_START
    ## Erledigt (Node)
    - [Crate + Datei + was]
    ## Erledigt (Spark-Client)
    - [Datei + Komponente + was]
    ## Nächste Node-Aufgabe
    [konkret — Phase, Datei, Funktion]
    ## Nächste Client-Aufgabe
    [konkret — Phase SA1/SA2, Screen, was zu tun]
    ## Halbfertig / Blocked
    [nichts / oder was und warum]
    ## Neue Erkenntnisse
    [API-Inkompatibilitäten, Design-Entscheidungen, Gotchas]

GRENZEN:
  - KEIN eigener Krypto-Algo
  - KEIN git push (kein Remote auf helix)
  - KEIN cargo build --release (außer Nightly)
  - KEIN npm install im Spark-Client (nur npx expo install)
  - KEINE Breaking Changes ohne Not"

cd "$PROJECT"
source "$HOME/.cargo/env"
printf '%s' "$PROMPT" | "$CLAUDE" \
  --dangerously-skip-permissions \
  --print \
  --max-turns 80 \
  --input-format text

EXIT_CODE=$?

# Abschluss-Notification: letzten State lesen für kompakte Zusammenfassung
NODE_DONE=$(grep -A2 "## Erledigt (Node)" "$STATE_FILE" 2>/dev/null | tail -1 | sed 's/^- //' | cut -c1-80 || echo "?")
APP_DONE=$(grep -A2 "## Erledigt (App)" "$STATE_FILE" 2>/dev/null | tail -1 | sed 's/^- //' | cut -c1-80 || echo "?")
NEXT_NODE=$(grep -A1 "## Nächste Node-Aufgabe" "$STATE_FILE" 2>/dev/null | tail -1 | cut -c1-60 || echo "?")

if [ "$EXIT_CODE" = "0" ]; then
  if [ "$IS_NIGHTLY" = "true" ]; then
    # Nightly: auch Build-Ergebnis melden
    NODE_BIN=$(ls -t "$BUILD_DIR"/helix-nightly-* 2>/dev/null | head -1 | xargs basename 2>/dev/null || echo "kein Build")
    notify "✅ Helix Nightly fertig — Node: $NODE_DONE | App: $APP_DONE | Binary: $NODE_BIN"
  else
    notify "✅ Helix Session fertig — Node: $NODE_DONE | App: $APP_DONE | Nächstes: $NEXT_NODE"
  fi
else
  notify "⚠️ Helix Session mit Fehler beendet (exit $EXIT_CODE) — Log: /tmp/helix-cron-4h.log"
fi

rm -f "$LOCKFILE"
echo "=== Helix Dev-Session beendet (exit $EXIT_CODE): $(date '+%H:%M') ==="
# Kein schedule_next — Cron (0 5,9,13,17,21) übernimmt.
