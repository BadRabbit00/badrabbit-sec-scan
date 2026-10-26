# sec-scan — один гейт безопасности для CI и локального прогона.
# Окружение (semgrep, gitleaks, trivy, osv-scanner, bandit, syft, jq) задаёт
# Nix-обёртка; голым bash этот файл не запускается.
#
#   sec-scan [-o DIR] [--fail-on critical|high|medium|none] [--skip a,b]
#            [--no-history] [PATH]
#
# Проверки: secrets (gitleaks), sast (semgrep, bandit), deps (trivy vuln +
# osv-scanner), iac (trivy misconfig), sbom (syft, CycloneDX).
# Проектные настройки — в PATH/.sec/: semgrep/*.yaml (свои правила),
# gitleaks.toml, .gitleaksignore, .trivyignore.
# Отчёты: DIR/sarif/*.sarif (для GitHub code scanning), DIR/json/*.json,
# DIR/sbom.cdx.json, DIR/summary.md. Код выхода 1 — есть находки на уровне
# --fail-on или выше (секреты валят всегда, кроме --fail-on none), 2 — ошибка.

usage() {
  cat <<'EOF'
sec-scan [-o DIR] [--fail-on critical|high|medium|none] [--skip a,b] [--no-history] [PATH]

  -o, --out DIR   reports directory (default .sec/reports)
  --fail-on LVL   gate threshold (default high); secrets always fail unless none
  --skip LIST     comma list of: secrets,sast,deps,iac,sbom
  --no-history    gitleaks scans the working tree only, not git history
  SEC_SCAN_SEMGREP_CONFIG="p/default ./rules"  override semgrep rulesets

Project settings in PATH/.sec/ are picked up automatically:
  .sec/semgrep/*.yaml  extra semgrep rules     .sec/gitleaks.toml  gitleaks config
  .sec/.gitleaksignore .sec/.trivyignore       accepted findings

sec-scan --redteam-gate RESULTS.json
  gate promptfoo eval results; REDTEAM_MAX_FAILURES (default 0)
Exit: 0 clean, 1 findings at/above threshold, 2 a scanner failed to run.
EOF
}

# Гейт по результатам promptfoo eval (JSON): провалы по плагинам атак,
# порог — REDTEAM_MAX_FAILURES (по умолчанию 0).
redteam_gate() {
  local file=$1 max=${REDTEAM_MAX_FAILURES:-0}
  [ -s "$file" ] || { echo "sec-scan: no promptfoo results: $file" >&2; exit 2; }
  local fails errs total
  fails=$(jq '.results.stats.failures' "$file")
  errs=$(jq '.results.stats.errors' "$file")
  total=$(jq '.results.results | length' "$file")
  {
    printf '# promptfoo\n\n- tests: %s\n- failed: %s\n- errors: %s\n- allowed failures: %s\n\n' \
      "$total" "$fails" "$errs" "$max"
    printf '| plugin | strategy | failed |\n|---|---|---|\n'
    jq -r '[.results.results[] | select(.success == false and .failureReason == 1)
            | {p: (.metadata.pluginId // .testCase.metadata.pluginId // "?"),
               s: (.metadata.strategyId // .testCase.metadata.strategyId // "basic")}]
           | group_by([.p, .s]) | sort_by(-length)[]
           | "| \(.[0].p) | \(.[0].s) | \(length) |"' "$file"
  } > "$(dirname "$file")/redteam-summary.md"
  cat "$(dirname "$file")/redteam-summary.md"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then cat "$(dirname "$file")/redteam-summary.md" >> "$GITHUB_STEP_SUMMARY"; fi
  [ "$fails" -le "$max" ] || exit 1
  exit 0
}

out=".sec/reports"; fail_on="high"; skip=","; history=1; target="."
while [ $# -gt 0 ]; do
  case "$1" in
    --redteam-gate) redteam_gate "$2" ;;
    -o|--out) out=$2; shift 2 ;;
    --fail-on) fail_on=$2; shift 2 ;;
    --skip) skip=",$2,"; shift 2 ;;
    --no-history) history=0; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "sec-scan: unknown flag $1" >&2; usage >&2; exit 2 ;;
    *) target=$1; shift ;;
  esac
done

case "$fail_on" in
  critical) trivy_sev="CRITICAL"; semgrep_sev="ERROR"; bandit_sev="HIGH" ;;
  high)     trivy_sev="CRITICAL,HIGH"; semgrep_sev="ERROR"; bandit_sev="HIGH" ;;
  medium)   trivy_sev="CRITICAL,HIGH,MEDIUM"; semgrep_sev="ERROR,WARNING"; bandit_sev="HIGH,MEDIUM" ;;
  none)     trivy_sev=""; semgrep_sev=""; bandit_sev="" ;;
  *) echo "sec-scan: --fail-on must be critical|high|medium|none" >&2; exit 2 ;;
esac

[ -d "$target" ] || { echo "sec-scan: no such directory: $target" >&2; exit 2; }
target=$(cd "$target" && pwd)
mkdir -p "$out/sarif" "$out/json"
out=$(cd "$out" && pwd)

# Отчёты не должны сканироваться сами собой, если лежат внутри цели.
rel_out=${out#"$target"/}
[ "$rel_out" = "$out" ] && rel_out=""

# Метрики semgrep и проверка версий — выключены: код клиента никуда не уходит.
export SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0
# Наборы правил semgrep; свои — через SEC_SCAN_SEMGREP_CONFIG (через пробел,
# можно локальный каталог с YAML для офлайн-режима).
semgrep_configs=${SEC_SCAN_SEMGREP_CONFIG:-"p/default p/secrets p/owasp-top-ten"}

# Проектные настройки сканеров из .sec/ — подхватываются, если есть.
sec="$target/.sec"
gitleaks_opts=(); trivy_opts=()
[ -f "$sec/gitleaks.toml" ] && gitleaks_opts+=(--config "$sec/gitleaks.toml")
[ -f "$sec/.gitleaksignore" ] && gitleaks_opts+=(--gitleaks-ignore-path "$sec/.gitleaksignore")
[ -f "$sec/.trivyignore" ] && trivy_opts+=(--ignorefile "$sec/.trivyignore")
[ -d "$sec/semgrep" ] && semgrep_configs="$semgrep_configs $sec/semgrep"

failed=""; errors=""
rows=""
row() { rows="$rows| $1 | $2 | $3 |"$'\n'; }
skipped() { case "$skip" in *",$1,"*) return 0 ;; *) return 1 ;; esac; }
note_fail() { failed="$failed $1"; }
note_error() { errors="$errors $1"; echo "sec-scan: $1 failed to run" >&2; }

# --- secrets ----------------------------------------------------------------
if ! skipped secrets; then
  echo "== secrets: gitleaks" >&2
  if [ "$history" = 1 ] && git -C "$target" rev-parse --git-dir >/dev/null 2>&1; then
    mode=(git "$target")
  else
    mode=(dir "$target")
  fi
  gitleaks "${mode[@]}" "${gitleaks_opts[@]}" --redact --no-banner --exit-code 3 \
    --report-format sarif --report-path "$out/sarif/gitleaks.sarif" >&2
  rc=$?
  n=$(jq '[.runs[].results[]] | length' "$out/sarif/gitleaks.sarif" 2>/dev/null || echo "?")
  case $rc in
    0) row secrets gitleaks "0" ;;
    3) row secrets gitleaks "**$n leaks**"; [ "$fail_on" != none ] && note_fail gitleaks ;;
    *) row secrets gitleaks "error ($rc)"; note_error gitleaks ;;
  esac
fi

# --- sast ---------------------------------------------------------------------
if ! skipped sast; then
  echo "== sast: semgrep" >&2
  cfg=(); for c in $semgrep_configs; do cfg+=(--config "$c"); done
  excl=(); [ -n "$rel_out" ] && excl=(--exclude "$rel_out")
  if semgrep scan "${cfg[@]}" "${excl[@]}" --metrics off --quiet \
       --json-output "$out/json/semgrep.json" --sarif-output "$out/sarif/semgrep.sarif" \
       "$target" >/dev/null; then
    total=$(jq '.results | length' "$out/json/semgrep.json")
    gate=0
    [ -n "$semgrep_sev" ] && gate=$(jq --arg s "$semgrep_sev" \
      '[.results[] | select(.extra.severity as $v | ($s | split(",") | index($v)))] | length' "$out/json/semgrep.json")
    row sast semgrep "$total (gate: $gate)"
    [ "$gate" -gt 0 ] && note_fail semgrep
  else
    row sast semgrep "error"; note_error semgrep
  fi

  if [ -n "$(find "$target" -name '*.py' -not -path '*/.*' -print -quit)" ]; then
    echo "== sast: bandit" >&2
    excl=(); [ -n "$rel_out" ] && excl=(-x "$target/$rel_out")
    bandit -r "$target" -q "${excl[@]}" -f json -o "$out/json/bandit.json" >/dev/null 2>&1
    if [ -s "$out/json/bandit.json" ]; then
      total=$(jq '.results | length' "$out/json/bandit.json")
      gate=0
      [ -n "$bandit_sev" ] && gate=$(jq --arg s "$bandit_sev" \
        '[.results[] | select(.issue_severity as $v | ($s | split(",") | index($v)))] | length' "$out/json/bandit.json")
      row sast bandit "$total (gate: $gate)"
      [ "$gate" -gt 0 ] && note_fail bandit
    else
      row sast bandit "error"; note_error bandit
    fi
  fi
fi

# --- deps + iac (одним прогоном trivy) ---------------------------------------
scanners=()
skipped deps || scanners+=(vuln)
skipped iac || scanners+=(misconfig)
if [ ${#scanners[@]} -gt 0 ]; then
  echo "== deps/iac: trivy (${scanners[*]})" >&2
  sc=$(IFS=,; echo "${scanners[*]}")
  skipdirs=(); [ -n "$rel_out" ] && skipdirs=(--skip-dirs "$rel_out")
  if trivy fs --quiet --scanners "$sc" "${skipdirs[@]}" "${trivy_opts[@]}" --format json \
       --output "$out/json/trivy.json" "$target" &&
     trivy convert --quiet --format sarif --output "$out/sarif/trivy.sarif" "$out/json/trivy.json"; then
    count() {
      jq --arg s "$1" --arg k "$2" '
        [.Results[]? | .[$k][]? | select(.Severity as $v | ($s | split(",") | index($v)))] | length' \
        "$out/json/trivy.json"
    }
    all="CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN"
    if ! skipped deps; then
      gate=0; [ -n "$trivy_sev" ] && gate=$(count "$trivy_sev" Vulnerabilities)
      row deps "trivy vuln" "$(count "$all" Vulnerabilities) (gate: $gate)"
      [ "$gate" -gt 0 ] && note_fail trivy-vuln
    fi
    if ! skipped iac; then
      gate=0; [ -n "$trivy_sev" ] && gate=$(count "$trivy_sev" Misconfigurations)
      row iac "trivy misconfig" "$(count "$all" Misconfigurations) (gate: $gate)"
      [ "$gate" -gt 0 ] && note_fail trivy-misconfig
    fi
  else
    row deps/iac trivy "error"; note_error trivy
  fi
fi

# osv-scanner — второе мнение по зависимостям, только отчёт (дубли с trivy).
if ! skipped deps; then
  echo "== deps: osv-scanner (report only)" >&2
  osv-scanner scan source -r --format sarif --output "$out/sarif/osv.sarif" "$target" >/dev/null 2>&1
  rc=$?
  case $rc in
    0|1) row deps "osv-scanner" "$(jq '[.runs[].results[]] | length' "$out/sarif/osv.sarif" 2>/dev/null || echo "?") (report only)" ;;
    128) row deps "osv-scanner" "no lockfiles" ; rm -f "$out/sarif/osv.sarif" ;;
    *) row deps "osv-scanner" "error ($rc)"; rm -f "$out/sarif/osv.sarif" ;;
  esac
fi

# --- sbom ---------------------------------------------------------------------
if ! skipped sbom; then
  echo "== sbom: syft" >&2
  if syft scan "dir:$target" --quiet ${rel_out:+--exclude "./$rel_out/**"} \
       -o "cyclonedx-json=$out/sbom.cdx.json"; then
    row sbom syft "$(jq '.components | length' "$out/sbom.cdx.json") components"
  else
    row sbom syft "error"; note_error syft
  fi
fi

# --- summary ------------------------------------------------------------------
{
  # shellcheck disable=SC2016  # обратные кавычки — разметка Markdown, не подстановка
  printf '# sec-scan\n\n- target: `%s`\n- fail-on: `%s`\n- date: %s\n\n' "$target" "$fail_on" "$(date -Iseconds)"
  printf '| check | tool | findings |\n|---|---|---|\n%s\n' "$rows"
  if [ -n "$failed" ]; then printf '**FAILED:**%s\n' "$failed"; else printf '**PASSED**\n'; fi
  [ -n "$errors" ] && printf '\n**Tool errors:**%s\n' "$errors"
} > "$out/summary.md"
cat "$out/summary.md"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then cat "$out/summary.md" >> "$GITHUB_STEP_SUMMARY"; fi

[ -n "$errors" ] && exit 2
[ -n "$failed" ] && exit 1
exit 0
