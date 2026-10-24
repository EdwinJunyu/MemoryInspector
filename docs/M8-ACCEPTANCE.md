# MemoryInspector 0.0.8 — Milestone 8 acceptance checklist

**Status: release candidate.** Automated CI cannot substitute for Windows 10 and 11 desktop validation or a 24-hour GUI run.

## Automated acceptance (safe)

- Windows PowerShell 5.1 parsing of all project scripts.
- Existing M1–M7 regression tests, with M8 fail-closed invalid-input and damaged-settings tests.
- Short read-only collector telemetry probe on GitHub-hosted Windows Server runner.
- Disposable runner protected installation, replay and hash-tamper rejection, safe uninstall preserving protected audit/policy.
- All required jobs must pass before considering a stable release.

## Manual Windows 10 AND Windows 11 acceptance (VM / non-production PC)

Record commit SHA, OS build, PowerShell version, start/end times, result, and sanitized evidence.

- [ ] Non-admin STA WinForms GUI starts without unexpected UAC.
- [ ] Processes, Overview, Services, History and Settings screens render and remain responsive.
- [ ] Memory counters match the meaning of Task Manager / Performance Monitor, not necessarily the same refresh timestamp.
- [ ] Tray minimization keeps sampling; explicit Quit stops it and no elevated child remains.
- [ ] Inaccessible process metrics show unknown/partial, never fabricated zero.
- [ ] PID reuse, process restarts and sleep/resume do not splice unrelated history.
- [ ] Reopen app: JSONL 7-day raw/90-day aggregate policy, rotation, truncated-tail repair, and disk budget are consistent.
- [ ] Confirmed graceful close affects only the chosen disposable GUI application; cancellation does nothing.
- [ ] Danger mode disabled by default; forced termination tested only with a disposable, unsaved-data-free test app.
- [ ] Unknown/system/critical/service-host processes cannot be forcibly terminated.
- [ ] UAC cancellation, invalid target, replay, policy tamper and missing audit all fail closed.
- [ ] Only an approved, disposable test service can be stopped and manually restarted.
- [ ] Running dependent service, auto-restart and timeout do not cause cascade, retries, host kill or startup type edits.
- [ ] Release report distinguishes target process bytes from system net Commit changes.
- [ ] Upgrade from protected 0.0.7 to 0.0.8 preserves allowlist/audit and enforces manifest.
- [ ] Uninstaller removes only controlled files and retains user data and privileged audit by default.
- [ ] Inject storage errors, truncated JSONL, access-denied CIM, disk full, sleep/resume on isolated test host.
- [ ] Measure idle GUI CPU target <1%, working set target <200 MiB, normal UI response target <1 second.
- [ ] Stress hundreds of processes and ensure sample backpressure does not hang GUI.
- [ ] Real GUI remains open or in tray for >=24 hours with no crash; evaluate trend, leaks, missed samples.

## Read-only collector soak

On each desktop OS, launch from Windows PowerShell 5.1:

    powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\AcceptanceSoak.ps1 -DurationMinutes 1440 -IntervalSeconds 10

This generates a JSON report with sample validity, gaps, P95 collector time and *CLI collector* resource consumption. Run separately from the 24-hour GUI observation. These numbers are not GUI resource metrics.

## Stable release gate

Do not create an official Stable v2 release or tag until automated checks AND desktop Windows 10/11 manual checks pass, especially all safety-critical cases. Keep unverified privileged features disabled. An unrun 24-hour test must remain NOT TESTED, not PASS.

For rollback, preserve audits/policy and user data. A downgrade may require manual verification of protected ACLs and manifest; the installer does not promise automatic downgrade.


## Read-only 24-hour GUI resource observer

While the GUI is already running, identify its own powershell.exe PID (avoid confusing it with the separate elevated executor). From a SECOND Windows PowerShell 5.1 terminal run:

    .\AcceptanceGuiMonitor.ps1 -TargetPid <GUI_PID> -DurationMinutes 1440 -IntervalSeconds 10

This observes the *actual GUI process* and saves per-interval RAM, Private Bytes, normalized CPU and window responsiveness to CSV, plus JSON summary. It never kills or starts the target. PID + creation time are checked on every sample. Use it alongside actual human/automation UI-latency checks; responsiveness based on MainWindowHandle is informative, not definitive. Do not interpret raw observer results as proof of full acceptance.
