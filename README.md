# ETW-Wazuh-Integration
# LargeUploadMonitor

Real-time large file upload / data-exfiltration detector for Windows endpoints, built on **ETW (Event Tracing for Windows)** kernel events and shipped as a Windows Service. Integrates with **Wazuh** for log collection, decoding, alerting, and **Shuffle** for SOAR automation.

This is a from-scratch C# rewrite of a previous Python polling-based detector. Instead of checking system state on a timer, it subscribes directly to Windows kernel ETW providers and is notified the instant a relevant file or network event occurs — the same mechanism Sysmon and Procmon are built on.

---

## Table of Contents

- [Architecture](#architecture)
- [Repository Structure & Workflow](#repository-structure--workflow)
  - [`LargeUploadMonitor.csproj`](#largeuploadmonitorcsproj)
  - [`Worker.cs`](#workercs)
  - [`AlertWriter.cs`](#alertwritercs)
  - [`Program.cs`](#programcs)
- [Build](#build)
- [Deploy](#deploy)
- [Service Management](#service-management)
- [Configuration](#configuration)
- [Alert Format](#alert-format)
- [Wazuh Integration](#wazuh-integration)
  - [Agent-side: `ossec.conf`](#agent-side-ossecconf)
  - [Manager-side: Decoder](#manager-side-decoder)
  - [Manager-side: Rule](#manager-side-rule)
  - [SOAR: Shuffle Integration](#soar-shuffle-integration)

---

## Architecture

```
 ┌───────────────────────────┐        ┌────────────────────────────┐
 │  Kernel-File provider     │        │  Kernel-Network provider   │
 │  (FileIOCreate)           │        │  (TcpIpSend / V6)          │
 └─────────────┬─────────────┘        └──────────────┬─────────────┘
               │ process, path, size                  │ pid, bytes, dest
               ▼                                       ▼
      ┌──────────────────┐                   ┌───────────────────┐
      │ _filesByProc     │                   │ _net              │
      │ keyed by PROCESS │                   │ keyed by PID      │
      │ NAME             │                   │                   │
      └────────┬─────────┘                   └─────────┬─────────┘
               │                                          │
               └─────────────────┐      ┌─────────────────┘
                                  ▼      ▼
                         ┌───────────────────────┐
                         │ AlertCheckLoop (5s)   │
                         │ – sums bytes/window   │
                         │ – matches file ↔ proc │
                         │ – cooldown gate       │
                         └──────────┬────────────┘
                                    ▼
                         ┌───────────────────────┐
                         │ AlertWriter           │
                         │ – monitor.log         │
                         │ – Windows Event Log   │
                         └──────────┬────────────┘
                                    ▼
                         ┌───────────────────────┐
                         │ Wazuh Agent           │
                         │ <localfile> tail      │
                         └──────────┬────────────┘
                                    ▼
                    Wazuh Manager → Decoder → Rule → Shuffle (SOAR)
```

**Why ETW, not polling:** the old approach polled system-wide network counters every 15 seconds and tried to correlate spikes with recently-touched files after the fact — by which point the file handle was already closed and the byte count was already polluted by unrelated background traffic (Teams, OneDrive, browser sync). ETW flips this: the kernel pushes `FileIOCreate` and `TcpIpSend` events to the service the instant they happen, with exact per-process attribution and zero detection lag.

**Why files are keyed by process name, not PID:** Chrome (and Edge, Teams, and most modern multi-process apps) splits work across processes — a *renderer* process opens the file the user selects (fires `FileIOCreate`), while a separate *network service* process owns the socket and sends the bytes (fires `TcpIpSend`). These are different PIDs sharing the same process name. Keying the file cache by name (not PID) is what makes correlation work across this split; a PID-keyed lookup would never match and every browser upload would report `filename=Unknown`.

---

## Repository Structure & Workflow

```
LargeUploadMonitor/
├── LargeUploadMonitor.csproj   # Project file — target framework, deps, publish settings
├── Program.cs                  # Entry point — CLI commands + Windows Service host bootstrap
├── Worker.cs                   # MonitorWorker — the ETW listener + correlation engine
└── AlertWriter.cs              # AlertWriter — writes alerts to monitor.log + Event Log
```

Below is what each file is responsible for and how data moves between them, in the order it's actually touched at runtime.

### `LargeUploadMonitor.csproj`

Project manifest. Key settings:

```xml
<Project Sdk="Microsoft.NET.Sdk.Worker">

  <PropertyGroup>
    <TargetFramework>net8.0-windows</TargetFramework>
    <RuntimeIdentifier>win-x64</RuntimeIdentifier>
    <!--
      Self-contained + single file = one .exe shipped to each endpoint.
      No .NET runtime install needed on target machines.
    -->
    <SelfContained>true</SelfContained>
    <PublishSingleFile>true</PublishSingleFile>
    <PublishTrimmed>false</PublishTrimmed>   <!-- TraceEvent uses reflection -->
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <AssemblyName>LargeUploadMonitor</AssemblyName>
    <RootNamespace>LargeUploadMonitor</RootNamespace>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
  </PropertyGroup>

  <ItemGroup>
    <!-- Windows service host -->
    <PackageReference Include="Microsoft.Extensions.Hosting.WindowsServices" Version="8.0.0" />
    <!-- ETW wrapper — this is the SAME library Microsoft Sysmon and PerfView use -->
    <PackageReference Include="Microsoft.Diagnostics.Tracing.TraceEvent"    Version="3.1.7" />
  </ItemGroup>

</Project>
```

Two dependencies do all the heavy lifting: `Microsoft.Extensions.Hosting.WindowsServices` turns the .NET Generic Host into an installable Windows Service, and `Microsoft.Diagnostics.Tracing.TraceEvent` is the managed wrapper around raw ETW — the same library Sysmon and PerfView themselves are built on. `PublishTrimmed` is explicitly disabled because `TraceEvent` relies on reflection internally and trimming would break it at runtime.

### `Program.cs`

**Entry point.** This is the first file that runs, and it branches two ways depending on how the `.exe` was invoked:

1. **CLI mode** (`args.Length > 0`) — handles `install`, `start`, `stop`, `restart`, `remove`, `status`. These are thin wrappers around `sc.exe` that register/control the Windows Service. Used once at deployment time and occasionally for maintenance.
2. **Service mode** (no args — this is how the Service Control Manager launches it) — builds a .NET Generic Host via `Host.CreateDefaultBuilder`, registers it as a Windows Service with `.UseWindowsService()`, wires up Event Log logging, and registers two services in DI:
   - `AlertWriter` as a singleton (shared across the app's lifetime)
   - `MonitorWorker` as a hosted `BackgroundService` (this is where the actual detection logic lives)

```csharp
var builder = Host.CreateDefaultBuilder(args)
    .UseWindowsService(o => o.ServiceName = ServiceName)
    .ConfigureLogging(logging => { /* Event Log sink */ })
    .ConfigureServices((_, services) =>
    {
        services.AddSingleton<AlertWriter>();
        services.AddHostedService<MonitorWorker>();
    });

await builder.Build().RunAsync();
```

Once `RunAsync()` is called, control passes to `MonitorWorker.ExecuteAsync()` and stays there for the lifetime of the service.

### `Worker.cs`

**The detection engine.** This is the largest and most important file — it owns the ETW session, the correlation state, and the alert-triggering logic. Execution flow inside `MonitorWorker`:

1. **Startup** — opens a single ETW kernel session (`EtwSessionName = "LargeUploadMonitorETW"`) and subscribes to two kernel providers:
   - `Microsoft-Windows-Kernel-File` → `FileIOCreate` events
   - `Microsoft-Windows-Kernel-Network` → `TcpIpSend` / `TcpIpSendIPV6` events

2. **On every `FileIOCreate` event:**
   - Resolves the NT device path (`\Device\HarddiskVolume3\...`) to a Win32 path (`C:\...`) using a drive map built once at startup via `QueryDosDevice`.
   - Filters out noise: Windows system directories, `Program Files`, anything under `AppData` (browser cache, app profiles — never a real user upload), and any extension not on the upload-relevant allowlist (archives, documents, media, source/config files, executables).
   - If the file passes filtering, its process name, full path, and exact size (`FileInfo.Length`) are recorded into `_filesByProc`, **keyed by process name** — not PID (see Architecture above for why).

3. **On every `TcpIpSend` / `TcpIpSendIPV6` event:**
   - Skips loopback traffic (`127.x.x.x`, `::1`) — that's inter-process IPC, not an upload.
   - Accumulates the byte count into `_net`, keyed by **PID**, within a rolling window (`WindowSec = 120` seconds).

4. **Every `CheckIntervalMs` (5 seconds), the alert-check loop runs:**
   - For each PID with rolling bytes over `ThresholdBytes`, resolves the PID to its process name.
   - Looks up `_filesByProc[processName]` for a matching file — applying two filters: only files opened *after* the previous alert for that process (prevents stale cache entries from bleeding into a new alert), and preferring the *most recently opened* file (not the largest — fixes a bug where an old, larger, unrelated cached file would get blamed for a new, smaller upload).
   - If no file is found, the process is checked against `HighRiskCapable` (CLI tools like `curl.exe`, `rclone.exe`, `powershell.exe` — suspicious even with `filename=Unknown`) vs. requiring a filename for browser/cloud-sync apps (`BrowserCapable` — prevents background sync/streaming traffic from alerting).
   - If a process passes the cooldown gate (`CooldownSec = 60`, per process name) and either has a matched file or is high-risk, it calls `AlertWriter.WriteAlert(...)`.
   - The PID's accumulator (`_net[pid]`) is cleared immediately on firing, so the same bytes can't trigger a second alert once the cooldown expires.

5. **Config constants** at the top of the class control all of this behavior — see [Configuration](#configuration) below.

```csharp
// MonitorWorker.cs — Configuration
private const int  ThresholdMb      = 5;
private const int  WindowSec        = 120;
private const int  FileCacheSec     = 180;
private const int  CooldownSec      = 60;
private const int  CheckIntervalMs  = 5_000;
private const int  MaxDestinations  = 10;
private const string EtwSessionName = "LargeUploadMonitorETW";
```

`Worker.cs` calls into `AlertWriter` exactly once per detected event — everything upstream of that call is detection logic; everything downstream is output/logging.

### `AlertWriter.cs`

**The output layer.** Receives a fully-formed detection from `Worker.cs` and is responsible for getting it durably recorded in two places:

1. **`C:\LargeUploadMonitor\monitor.log`** — a flat, append-only log file, written under a lock to avoid interleaved writes. Self-rotates at 5 MB (`MaxLogBytes`), keeping 3 rotated generations (`monitor.log.1`, `.2`, `.3`). This is the file the **Wazuh agent tails** (see [Agent-side configuration](#agent-side-ossecconf)).
2. **Windows Application Event Log**, under the source name `LargeUploadMonitor` (event ID `9001` for alerts, `9000` for info/error). Created automatically on first run via `EventLog.CreateEventSource` if it doesn't already exist.

Both writes are best-effort and wrapped in try/catch — a logging failure should never crash the detection service itself.

```csharp
public void WriteAlert(
    int pid, string procName, string filename, string filetype,
    string destination, long deltaBytes, long fileSizeBytes, int thresholdMb)
{
    // Use actual file size when known — exact, not network delta-derived.
    double reportMb = fileSizeBytes > 0
        ? fileSizeBytes / (1024.0 * 1024.0)
        : deltaBytes    / (1024.0 * 1024.0);

    string msg =
        "LARGE_UPLOAD_DETECTED" +
        $" | process={procName}" +
        $" | pid={pid}" +
        $" | filename={safe_filename}" +
        $" | filetype={safe_filetype}" +
        $" | destination={destination}" +
        $" | uploaded_mb={reportMb:F2}" +
        $" | threshold_mb={thresholdMb}";

    AppendLogLine(msg, "WARNING");
    WriteEventLog(msg, EventIdAlert, EventLogEntryType.Warning);
}
```

This format is deliberately identical to the previous Python version's output, so the existing Wazuh decoder and rule (below) work unmodified.

---

## End-to-End Workflow Summary

| Step | File | What happens |
|---|---|---|
| 1 | `Program.cs` | Service starts under SCM, builds Generic Host, hands off to `MonitorWorker` |
| 2 | `Worker.cs` | Subscribes to ETW kernel providers; listens 24/7 |
| 3 | `Worker.cs` | `FileIOCreate` → file cached by process name; `TcpIpSend` → bytes accumulated by PID |
| 4 | `Worker.cs` | Every 5s, alert-check loop correlates file ↔ network, applies cooldown |
| 5 | `AlertWriter.cs` | Writes `LARGE_UPLOAD_DETECTED` line to `monitor.log` + Windows Event Log |
| 6 | Wazuh Agent | Tails `monitor.log` via `<localfile>`, ships to manager |
| 7 | Wazuh Manager | Decoder extracts fields → Rule `100900` fires (level 12) |
| 8 | Wazuh Manager | Integration block forwards the alert to Shuffle as JSON |
| 9 | Shuffle | Playbook picks up the webhook for automated triage |

---

## Build

Requires the .NET 8 SDK on the build machine.

```bash
dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true
```

Output:

```
bin\Release\net8.0-windows\win-x64\publish\LargeUploadMonitor.exe
```

Self-contained + single-file means this one `.exe` (~70 MB) is the entire deployment artifact — no .NET runtime install needed on the target endpoint.

## Deploy

On the target PC, **as Administrator**:

```bash
mkdir C:\LargeUploadMonitor
copy LargeUploadMonitor.exe C:\LargeUploadMonitor\
C:\LargeUploadMonitor\LargeUploadMonitor.exe install
C:\LargeUploadMonitor\LargeUploadMonitor.exe start
```

`install` registers the service (`LocalSystem`, `start=auto`) via `sc.exe`; `start` launches it immediately. Being `start=auto` under `LocalSystem` means it survives reboots without any additional scheduled-task wiring.

## Service Management

```bash
LargeUploadMonitor.exe install    # Register as Windows service
LargeUploadMonitor.exe start      # Start the service
LargeUploadMonitor.exe stop       # Stop the service
LargeUploadMonitor.exe restart    # Stop then start
LargeUploadMonitor.exe remove     # Stop and unregister
LargeUploadMonitor.exe status     # Print current service state
```

## Configuration

All tunables live as `private const` fields at the top of `MonitorWorker.cs`. There's no external config file — change the constant and rebuild:

```csharp
private const int  ThresholdMb      = 5;       // file/upload size (MB) that triggers an alert
private const int  WindowSec        = 120;     // rolling network window — covers large/slow uploads
private const int  FileCacheSec     = 180;     // how long file-open records stay cached
private const int  CooldownSec      = 60;      // min seconds between alerts per process name
private const int  CheckIntervalMs  = 5_000;   // alert-check loop frequency
private const int  MaxDestinations  = 10;      // cap on distinct destination IPs per alert
```

Lowering `ThresholdMb` catches smaller exfiltration attempts at the cost of more noise; shortening `CheckIntervalMs` tightens detection latency at a small CPU cost. Tune to your environment's baseline upload behavior.

## Alert Format

```
2026-06-21 14:32:07 [WARNING] LARGE_UPLOAD_DETECTED | process=chrome.exe | pid=14820 | filename=Q3_financials.xlsx | filetype=.xlsx | destination=104.21.45.12:443 | uploaded_mb=12.41 | threshold_mb=5
```

Written simultaneously to:
- `C:\LargeUploadMonitor\monitor.log` (rotates at 5 MB, 3 generations kept)
- Windows Application Event Log, source `LargeUploadMonitor`, event ID `9001`

---

## Wazuh Integration

### Agent-side: `ossec.conf`

On every monitored Windows endpoint, add this `<localfile>` block so the Wazuh agent tails the monitor's log file:

```xml
<localfile>
  <location>C:\LargeUploadMonitor\monitor.log</location>
  <log_format>syslog</log_format>
</localfile>
```

This goes inside the Windows agent's `ossec.conf` (typically `C:\Program Files (x86)\ossec-agent\ossec.conf`), alongside any other `<localfile>` blocks already configured.

### Manager-side: Decoder

On the Wazuh manager, in `/var/ossec/etc/decoders/large_upload_decoder.xml`:

```xml
<decoder name="large_upload_monitor">
  <prematch>LARGE_UPLOAD_DETECTED</prematch>
</decoder>

<decoder name="large_upload_monitor_fields">
  <parent>large_upload_monitor</parent>
  <regex>process=(\S+) \| pid=(\d+) \| filename=(\S+) \| filetype=(\S+) \| destination=(\S+) \| uploaded_mb=(\S+) \| threshold_mb=(\S+)</regex>
  <order>proc_name,id,filename,status,url,size,extra_data</order>
</decoder>
```

The first decoder identifies the log line by prematch; the second, parented to it, extracts the structured fields via regex.

### Manager-side: Rule

In the manager's local rules file:

```xml
<group name="large_upload_monitor,">

  <rule id="100900" level="12">
    <match>LARGE_UPLOAD_DETECTED</match>
    <description>Large file upload detected</description>
  </rule>

</group>
```

Level 12 — high enough to require analyst attention, without being treated as an automatic P1; it's a strong signal meant to feed broader correlation rather than stand alone as a confirmed breach.

### SOAR: Shuffle Integration

In `ossec.conf` on the manager, forwarding rule `100900` hits to a [Shuffle](https://shuffler.io/) webhook as JSON:

```xml
<integration>
  <name>shuffle</name>
  <hook_url>http://<Shuffle_IP>:3001/api/v1/hooks/webhook_<id></hook_url>
  <rule_id>100900</rule_id>
  <alert_format>json</alert_format>
</integration>
```

This closes the loop end-to-end — kernel event → ETW → alert → Wazuh decoder/rule → Shuffle playbook — with no manual analyst step required just to get the alert in front of an automated response workflow.
