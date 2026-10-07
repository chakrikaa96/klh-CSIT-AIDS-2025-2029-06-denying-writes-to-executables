#!/usr/bin/env bash
# ExecGuard - live web demonstration.
#
# Runs the full ExecGuard demonstration and streams the results to a local web
# page that updates in real time, instead of printing them to the terminal.
#
# It:
#   1. Creates an isolated sandbox under /opt/execguard-demo and protects it.
#   2. Starts a small local web server (Python stdlib) and opens the page.
#   3. Runs every check, writing each PASS/FAIL to results.json as it happens.
#   4. Leaves the page up until you press Enter, then cleans up.
#
# Requirements: root, the ExecGuard daemon running, and python3.
#   sudo systemctl start execguard
#   sudo ./src/scripts/web-demo.sh
#
# Environment overrides: PORT (default 8080).

set -uo pipefail

DEMO=/opt/execguard-demo
PROTDIR="$DEMO/protected"
APP="$PROTDIR/app"
SCRIPT="$PROTDIR/script.sh"
UPDATER="$DEMO/eg-updater"
RUN="$DEMO/run"
PORT="${PORT:-8080}"

PASS=0
FAIL=0
seq=0
STARTED="$(date '+%Y-%m-%d %H:%M:%S')"
SERVER_PID=""

# --- prerequisites ----------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo $0" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to serve the results page." >&2
    exit 1
fi
if ! egctl status >/dev/null 2>&1; then
    echo "ExecGuard daemon is not reachable. Start it first:" >&2
    echo "  sudo systemctl start execguard" >&2
    exit 1
fi

SRC_UPDATER=""
for c in /usr/local/libexec/execguard/eg-updater "$(dirname "$0")/../../build/eg-updater"; do
    [[ -x "$c" ]] && SRC_UPDATER="$c" && break
done
if [[ -z "$SRC_UPDATER" ]]; then
    echo "eg-updater binary not found. Build the project first: make" >&2
    exit 1
fi

mkdir -p "$RUN"

cleanup() {
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null
    egctl unprotect "$APP"    >/dev/null 2>&1 || true
    egctl unprotect "$SCRIPT" >/dev/null 2>&1 || true
    egctl maintenance disable >/dev/null 2>&1 || true
    egctl enforce 1           >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- results writer ---------------------------------------------------------
STEPS_FILE="$RUN/steps.tmp"
: > "$STEPS_FILE"

write_results() {
    local status="$1"
    {
        printf '{"status":"%s","started":"%s","pass":%d,"fail":%d,"total":%d,"steps":[' \
            "$status" "$STARTED" "$PASS" "$FAIL" "$seq"
        paste -sd, "$STEPS_FILE" 2>/dev/null
        printf ']}'
    } > "$RUN/results.json.tmp"
    mv -f "$RUN/results.json.tmp" "$RUN/results.json"
}

# emit <section> <name> <expected> <actual> <verdict>
emit() {
    seq=$((seq + 1))
    printf '{"seq":%d,"section":"%s","name":"%s","expected":"%s","actual":"%s","verdict":"%s"}\n' \
        "$seq" "$1" "$2" "$3" "$4" "$5" >> "$STEPS_FILE"
    write_results running
}

# check <section> <expected: allowed|blocked> <name> <command...>
check() {
    local section="$1" expect="$2" name="$3"; shift 3
    local actual verdict
    if "$@" >/dev/null 2>&1; then actual="allowed"; else actual="blocked"; fi
    if [[ "$actual" == "$expect" ]]; then verdict="PASS"; PASS=$((PASS + 1))
    else verdict="FAIL"; FAIL=$((FAIL + 1)); fi
    emit "$section" "$name" "$expect" "$actual" "$verdict"
    sleep 0.35   # brief pace so the live updates are visible during a demo
}

reset_app() { "$UPDATER" "$APP" "protected application v1" >/dev/null 2>&1 || true; }

# --- write the live results page --------------------------------------------
cat > "$RUN/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ExecGuard - Live Demonstration</title>
<style>
  :root{
    --bg:#f6f6f4; --card:#ffffff; --ink:#1a1a18; --muted:#6b6b66;
    --line:#e4e4de; --pass-bg:#e7f5ec; --pass:#1c7a45; --fail-bg:#fdecec;
    --fail:#b3261e; --accent:#0f6e56; --chip:#eef0ee;
  }
  @media (prefers-color-scheme: dark){
    :root{
      --bg:#17171a; --card:#202024; --ink:#ececec; --muted:#a0a0a0;
      --line:#33333a; --pass-bg:#12331f; --pass:#5dcaa5; --fail-bg:#3a1616;
      --fail:#f09595; --accent:#5dcaa5; --chip:#2a2a30;
    }
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       background:var(--bg);color:var(--ink);line-height:1.5}
  .wrap{max-width:860px;margin:0 auto;padding:24px 16px 64px}
  header{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:4px}
  h1{font-size:22px;font-weight:600;margin:0}
  .sub{color:var(--muted);font-size:14px}
  .status{display:inline-flex;align-items:center;gap:8px;padding:4px 12px;border-radius:999px;
          font-size:13px;font-weight:600;background:var(--chip)}
  .dot{width:9px;height:9px;border-radius:50%;background:var(--accent)}
  .dot.run{animation:pulse 1s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
  .cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:18px 0 24px}
  .stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
  .stat .n{font-size:28px;font-weight:600}
  .stat .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
  .n.pass{color:var(--pass)} .n.fail{color:var(--fail)}
  .section{margin:22px 0 8px;font-size:13px;font-weight:600;color:var(--muted);
           text-transform:uppercase;letter-spacing:.05em}
  .row{display:flex;align-items:center;gap:12px;background:var(--card);border:1px solid var(--line);
       border-radius:10px;padding:11px 14px;margin-bottom:8px;animation:fade .3s ease}
  @keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
  .row .name{flex:1;font-size:15px}
  .row .exp{font-size:12px;color:var(--muted);font-family:ui-monospace,Menlo,Consolas,monospace}
  .badge{font-size:12px;font-weight:700;padding:3px 10px;border-radius:6px}
  .badge.PASS{background:var(--pass-bg);color:var(--pass)}
  .badge.FAIL{background:var(--fail-bg);color:var(--fail)}
  .done{margin-top:26px;padding:16px;border-radius:12px;background:var(--card);
        border:1px solid var(--line);font-size:15px}
  .done.ok{border-color:var(--pass)} .done.bad{border-color:var(--fail)}
  .waiting{color:var(--muted);font-size:14px;padding:20px 0}
  footer{margin-top:32px;color:var(--muted);font-size:12px}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>ExecGuard</h1>
    <span class="sub">Live enforcement demonstration</span>
    <span id="status" class="status"><span class="dot run"></span> Connecting…</span>
  </header>

  <div class="cards">
    <div class="stat"><div id="c-total" class="n">0</div><div class="l">Checks run</div></div>
    <div class="stat"><div id="c-pass" class="n pass">0</div><div class="l">Passed</div></div>
    <div class="stat"><div id="c-fail" class="n fail">0</div><div class="l">Failed</div></div>
  </div>

  <div id="body"><div class="waiting">Waiting for the first result…</div></div>
  <div id="summary"></div>

  <footer>ExecGuard live demo. This page reads results.json from the demo run and refreshes automatically.</footer>
</div>

<script>
let timer = null;
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

function render(d){
  document.getElementById('c-total').textContent = d.total || 0;
  document.getElementById('c-pass').textContent  = d.pass  || 0;
  document.getElementById('c-fail').textContent  = d.fail  || 0;

  const st = document.getElementById('status');
  if(d.status === 'done'){
    st.innerHTML = '<span class="dot"></span> Complete';
  }else{
    st.innerHTML = '<span class="dot run"></span> Running…';
  }

  const body = document.getElementById('body');
  if(!d.steps || !d.steps.length){
    body.innerHTML = '<div class="waiting">Waiting for the first result…</div>';
  }else{
    let html = '', lastSection = null;
    for(const s of d.steps){
      if(s.section !== lastSection){
        html += '<div class="section">' + esc(s.section) + '</div>';
        lastSection = s.section;
      }
      html += '<div class="row">'
           +    '<span class="name">' + esc(s.name) + '</span>'
           +    '<span class="exp">expected ' + esc(s.expected) + ' &middot; got ' + esc(s.actual) + '</span>'
           +    '<span class="badge ' + esc(s.verdict) + '">' + esc(s.verdict) + '</span>'
           +  '</div>';
    }
    body.innerHTML = html;
  }

  const sum = document.getElementById('summary');
  if(d.status === 'done'){
    const ok = (d.fail || 0) === 0;
    sum.innerHTML = '<div class="done ' + (ok ? 'ok' : 'bad') + '">'
      + (ok ? 'All ' + d.total + ' checks passed. Protection behaved exactly as configured.'
            : d.fail + ' of ' + d.total + ' checks did not match the expected result.')
      + '</div>';
  }else{
    sum.innerHTML = '';
  }
}

async function tick(){
  try{
    const r = await fetch('results.json?_=' + Date.now(), {cache:'no-store'});
    if(!r.ok) return;
    const d = await r.json();
    render(d);
    if(d.status === 'done' && timer){ clearInterval(timer); timer = null; }
  }catch(e){ /* file not ready yet */ }
}
tick();
timer = setInterval(tick, 1000);
</script>
</body>
</html>
HTML

# Seed an initial results file so the page has something to read immediately.
write_results running

# --- start the web server ---------------------------------------------------
python3 -m http.server "$PORT" --bind 0.0.0.0 --directory "$RUN" >/dev/null 2>&1 &
SERVER_PID=$!
sleep 1

URL="http://127.0.0.1:$PORT/"
VM_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

echo "ExecGuard live demo is being served."
echo "  Local:      $URL"
[[ -n "$VM_IP" ]] && echo "  From host:  http://$VM_IP:$PORT/   (open this in your Mac browser if inside a VM)"
echo

# Try to auto-open a browser; fall back to the printed URL when no GUI exists.
if command -v xdg-open >/dev/null 2>&1 && [[ -n "${DISPLAY:-}" ]]; then
    xdg-open "$URL" >/dev/null 2>&1 &
    echo "Opening the page in your browser…"
else
    echo "No desktop browser available here (headless/VM)."
    echo "Open one of the URLs above in a browser to watch the run live."
fi
echo

# --- set up the protected sandbox -------------------------------------------
egctl enforce 1           >/dev/null 2>&1 || true
egctl maintenance disable >/dev/null 2>&1 || true
egctl unprotect "$APP"    >/dev/null 2>&1 || true
egctl unprotect "$SCRIPT" >/dev/null 2>&1 || true

mkdir -p "$PROTDIR"
printf '#!/bin/sh\necho "I am the protected application, version 1."\n' > "$APP"
chmod 0755 "$APP"
printf '#!/bin/sh\necho "protected helper script"\n' > "$SCRIPT"
chmod 0755 "$SCRIPT"
install -m 0755 "$SRC_UPDATER" "$UPDATER"

egctl protect "$APP"     >/dev/null
egctl protect "$SCRIPT"  >/dev/null
egctl trust   "$UPDATER" >/dev/null

echo "Running checks (watch the page update)…"

# --- 1. normal use ----------------------------------------------------------
check "Normal use still works" allowed "Read the protected file"    cat "$APP"
check "Normal use still works" allowed "Execute the protected file" "$APP"

# --- 2. modification blocked ------------------------------------------------
check "Unauthorized modification" blocked "Overwrite (shell redirect)" bash -c "echo pwned > '$APP'"
check "Unauthorized modification" blocked "Append to file"             bash -c "echo more >> '$APP'"
check "Unauthorized modification" blocked "Truncate file"              truncate -s 0 "$APP"
check "Unauthorized modification" blocked "In-place edit (sed -i)"     sed -i "s/version 1/HACKED/" "$APP"
check "Unauthorized modification" blocked "Overwrite bytes (dd)"       dd if=/dev/zero of="$APP" bs=1 count=1 conv=notrunc
check "Unauthorized modification" blocked "Python open('w')"           python3 -c "open('$APP','w').write('x')"

# --- 3. deletion and replacement --------------------------------------------
check "Deletion and replacement" blocked "Delete file (rm)" rm -f "$APP"
printf 'malware\n' > /tmp/eg_web_evil 2>/dev/null || true
check "Deletion and replacement" blocked "Replace via rename (mv)" mv -f /tmp/eg_web_evil "$APP"
check "Deletion and replacement" blocked "Delete via python unlink" python3 -c "import os; os.unlink('$APP')"

# --- 4. hardlink alias ------------------------------------------------------
if ln "$APP" "$DEMO/alias" 2>/dev/null; then
    check "Inode identity (hardlink)" blocked "Write via hardlink alias" bash -c "echo pwned > '$DEMO/alias'"
    rm -f "$DEMO/alias" 2>/dev/null || true
fi

# --- 5. trusted updater -----------------------------------------------------
check "Trusted updater" allowed "Trusted updater rewrites app" "$UPDATER" "$APP" "updated by trusted updater"
reset_app

# --- 6. maintenance mode ----------------------------------------------------
egctl maintenance enable --duration 60s >/dev/null
check "Maintenance mode" allowed "Write during maintenance window" bash -c "echo maint > '$APP'"
egctl maintenance disable >/dev/null
reset_app
check "Maintenance mode" blocked "Write after maintenance disabled" bash -c "echo pwned > '$APP'"

# --- 7. audit-only mode -----------------------------------------------------
egctl enforce 0 >/dev/null
check "Audit-only mode" allowed "Write in audit-only mode (logged)" bash -c "echo audit > '$APP'"
egctl enforce 1 >/dev/null
reset_app
check "Audit-only mode" blocked "Write after re-enabling enforce" bash -c "echo pwned > '$APP'"

# --- done -------------------------------------------------------------------
write_results done
echo
echo "Done: $PASS passed, $FAIL failed. Results are on the page."
echo
read -r -p "Press Enter to stop the server and clean up the sandbox… " _
