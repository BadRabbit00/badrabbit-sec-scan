# badrabbit-sec-scan

Security checks for any GitHub repository with one copied file. The project
needs no Nix, Docker or config: the workflow installs Nix on the runner,
fetches this flake and runs pinned scanners from it.

## Use in a project

```sh
mkdir -p .github/workflows
curl -fsSL https://raw.githubusercontent.com/BadRabbit00/badrabbit-sec-scan/main/badrabbit-sec-scan.yaml \
  -o .github/workflows/badrabbit-sec-scan.yaml
git add .github/workflows/badrabbit-sec-scan.yaml && git commit -m "ci: add security checks"
```

`badrabbit-sec-scan.yaml` sits in the root of this repository on purpose: it is
a file to copy, not a workflow of this repo.

## What runs

**`sec-scan`** — every push, PR and weekly:

| check   | tools | fails the build on (`--fail-on high`) |
|---------|-------|---------------------------------------|
| secrets | gitleaks over the whole git history | any leak |
| sast    | semgrep (`p/default`, `p/secrets`, `p/owasp-top-ten`), bandit for Python | semgrep ERROR, bandit HIGH |
| deps    | trivy (lockfiles of all ecosystems), osv-scanner (report only) | HIGH / CRITICAL |
| iac     | trivy misconfig: Dockerfile, compose, k8s, Terraform, Helm | HIGH / CRITICAL |
| sbom    | syft, CycloneDX | — |

Output: job summary, findings in the **Security → Code scanning** tab
(SARIF; private repos need GitHub Advanced Security), full reports in the
`sec-scan` artifact. Semgrep metrics are off; source code is not uploaded anywhere.

**`promptfoo`** — only if the project has its own `promptfooconfig.yaml`
(path: `PROMPTFOO_CONFIG` in the workflow). With a `redteam:` section it is a
red team (generate attacks → run → gate), otherwise a plain `promptfoo eval`
of your test cases, including Python asserts (`type: python`). The job fails
when more tests fail than `REDTEAM_MAX_FAILURES` (default 0).

## Settings

Repository → Settings → Secrets and variables → Actions:

| name | kind | default | meaning |
|---|---|---|---|
| `SEC_SCAN_FAIL_ON` | variable | `high` | `critical`, `high`, `medium`, `none` |
| `SEC_SCAN_SKIP` | variable | — | e.g. `sbom,iac` |
| `REDTEAM_MAX_FAILURES` | variable | `0` | failed promptfoo tests tolerated |
| `REDTEAM_TARGET_URL` | variable | — | for configs that use `{{ env.REDTEAM_TARGET_URL }}` |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `REDTEAM_API_KEY` | secrets | — | whatever your promptfoo config needs |

False positives: `# nosemgrep: <rule>` on the line, `.gitleaksignore`
(fingerprints from the report), `.trivyignore` (CVE ids).

## Run locally

```sh
nix run github:BadRabbit00/badrabbit-sec-scan -- .                 # same gate as CI
nix run github:BadRabbit00/badrabbit-sec-scan -- --help
nix run github:BadRabbit00/badrabbit-sec-scan#promptfoo -- eval
```

Exit codes: `0` clean, `1` findings at or above the threshold, `2` a scanner
failed to run.

## Updating the scanners

`nix flake update` here bumps every tool at once; projects that track `main`
pick it up on the next run. To freeze a project, pin a commit in its
workflow: `SEC_SCAN_FLAKE: github:BadRabbit00/badrabbit-sec-scan/<commit>`.

## License

MIT
