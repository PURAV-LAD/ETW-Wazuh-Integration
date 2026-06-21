using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace LargeUploadMonitor;

/*
 * HOW THIS WORKS
 *   Subscribe to kernel ETW events. Two providers run 24/7:
 *
 *    ① Microsoft-Windows-Kernel-File  (FileIOCreate)
 *         Fires the INSTANT a process opens a file.
 *         We record: process name, full path, file size — right then, before any upload.
 *
 *    ② Microsoft-Windows-Kernel-Network (TcpIpSend)
 *         Fires for every TCP packet sent, carrying PID + bytes + destination.
 *         We accumulate per-PID bytes in a rolling window.
 *
 *  Every 5 seconds we scan: for any PID where rolling bytes > THRESHOLD_MB,
 *  does its process name also have a recently-seen upload file?  If yes → alert.
 *
 *  WHY WE KEY FILES BY PROCESS NAME (not PID):
 *    Chrome (and Edge, Teams…) use a multi-process architecture:
 *      • Renderer process  (PID A) reads car.exe → fires FileIOCreate
 *      • Network process   (PID B) sends TCP     → fires TcpIpSend
 *    PID A ≠ PID B, so PID-keyed lookup never matched → filename=Unknown.
 *    Both processes share the same ProcessName "chrome.exe", so name-keyed
 *    lookup finds the file from the renderer when the network process alerts.
 *
 *  Result:
 *    Filename  → from FileIOCreate of ANY chrome.exe process (never Unknown)
 *    File size → from FileInfo.Length at open time (exact, not network delta)
 *    Process   → from the ETW event PID resolved to process name
 *    Dest IPs  → from TcpIpSend events for that specific network PID
 */

[SupportedOSPlatform("windows")]
public sealed class MonitorWorker : BackgroundService
{
    // ── Configuration ─────────────────────────────────────────────────────
    private const int  ThresholdMb      = 5;
    private const int  WindowSec        = 120;        // rolling network window — covers large/slow uploads
    private const int  FileCacheSec     = 180;        // keep file-open records for 3 minutes
    private const int  CooldownSec      = 60;         // min seconds between alerts per process name
    private const int  CheckIntervalMs  = 5_000;      // alert-check frequency
    private const int  MaxDestinations  = 10;         // cap IPs in one alert
    private const string EtwSessionName = "LargeUploadMonitorETW";

    private static readonly long ThresholdBytes = ThresholdMb * 1024L * 1024L;

    // ── Upload-capable processes — two tiers ─────────────────────────────
    //
    // Tier 1 — HighRiskCapable: CLI tools that are SUSPICIOUS by themselves.
    //   Alert even when filename=Unknown (if a script uploads without leaving
    //   a traceable file open, that's still worth alerting on).
    private static readonly HashSet<string> HighRiskCapable =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "curl.exe", "wget.exe", "winscp.exe", "pscp.exe", "ftp.exe", "sftp.exe",
            "rclone.exe", "s3cmd.exe", "robocopy.exe",
            "python.exe", "python3.exe", "powershell.exe", "pwsh.exe", "cmd.exe",
            "7z.exe", "winrar.exe", "rar.exe", "filezilla.exe",
        };
    
    // Tier 2 — BrowserCapable: browsers and cloud-sync apps.
    //   REQUIRE a filename. Without one, the traffic is background activity
    //   (YouTube buffering, Google Drive sync, Chrome extension updates) —
    //   NOT a user-initiated upload. Firing on that is a false positive.
    private static readonly HashSet<string> UploadCapable =
        new(StringComparer.OrdinalIgnoreCase)
        {
            // Browsers (Tier 2 — require filename)
            "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe", "iexplore.exe",
            // Cloud sync (Tier 2 — require filename)
            "onedrive.exe", "dropbox.exe", "googledrivesync.exe", "googledrive.exe", "box.exe",
            // Comms (Tier 2 — require filename)
            "teams.exe", "msteams.exe", "slack.exe", "zoom.exe", "skype.exe", "discord.exe",
            // Email (Tier 2 — require filename)
            "outlook.exe", "thunderbird.exe",
            // High-risk CLI tools also go here so they're caught by UploadCapable checks
            "curl.exe", "wget.exe", "winscp.exe", "pscp.exe", "ftp.exe", "sftp.exe",
            "rclone.exe", "s3cmd.exe", "robocopy.exe",
            "python.exe", "python3.exe", "powershell.exe", "pwsh.exe", "cmd.exe",
            "7z.exe", "winrar.exe", "rar.exe", "filezilla.exe",
        };

    // ── Extensions worth tracking ─────────────────────────────────────────
    private static readonly HashSet<string> UploadExtensions =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
            ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".odt", ".ods",
            ".csv", ".json", ".xml", ".sql", ".yaml", ".yml", ".env",
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp",
            ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".mp3", ".wav", ".flac",
            ".exe", ".msi", ".iso", ".img",
            ".py", ".js", ".ts", ".php", ".java", ".cpp", ".cs", ".sh", ".bat",
            ".db", ".sqlite", ".bak", ".dump",
            ".txt", ".md",
        };

    // ── Path hints: user-storage locations we care about ─────────────────
    private static readonly string[] UserPathHints =
    {
        @"\desktop\", @"\documents\", @"\downloads\",
        @"\pictures\", @"\videos\", @"\music\",
        @"\onedrive\", @"\dropbox\", @"\google drive\", @"\sharepoint\",
    };

    // ── Paths to ignore (system / app internals / junk) ──────────────────
    // Using Contains for appdata so it works regardless of drive letter.
    private static readonly string[] SystemStartsWith =
    {
        @"c:\windows\", @"c:\program files\", @"c:\program files (x86)\",
    };
    private const string AppDataMarker = @"\appdata\";   // checked with Contains

    // ── ETW record types ──────────────────────────────────────────────────

    /// <summary>Captured when an upload-capable process opens an upload-worthy file.</summary>
    private sealed record FileRecord(
        DateTime Timestamp,
        string   FullPath,
        string   FileName,
        string   Extension,
        long     SizeBytes);

    /// <summary>Captured for each TCP packet sent by any process.</summary>
    private sealed record NetRecord(
        DateTime Timestamp,
        long     Bytes,
        string   DestIp,
        int      DestPort);

    // ── State (thread-safe) ───────────────────────────────────────────────
    //
    // _filesByProc: keyed by process NAME (e.g. "chrome.exe"), NOT by PID.
    //   Reason: Chrome's renderer (PID A) reads the file; Chrome's network
    //   service (PID B) sends TCP. They share the ProcessName "chrome.exe"
    //   but have different PIDs. Name-based lookup finds the file that
    //   the renderer opened when the network process triggers the alert.
    //
    // _net:     keyed by PID — each TCP-sending process has its own entry.
    // _alerted: keyed by process NAME — cooldown per-app, not per-subprocess.
    private readonly ConcurrentDictionary<string, List<FileRecord>> _filesByProc = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<int,    List<NetRecord>>  _net         = new();
    private readonly ConcurrentDictionary<string, DateTime>         _alerted     = new(StringComparer.OrdinalIgnoreCase);

    private readonly AlertWriter           _alert;
    private readonly ILogger<MonitorWorker> _log;

    public MonitorWorker(AlertWriter alert, ILogger<MonitorWorker> log)
    {
        _alert = alert;
        _log   = log;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Service entry point
    // ─────────────────────────────────────────────────────────────────────

    protected override async Task ExecuteAsync(CancellationToken stopping)
    {
        _log.LogInformation("LargeUploadMonitor (ETW) starting.");
        _alert.WriteInfo(
            $"LARGE_UPLOAD_MONITOR_STARTED | threshold_mb={ThresholdMb} | window_sec={WindowSec}");

        // Kill any leftover ETW session from a previous crash so we can recreate it.
        try { TraceEventSession.GetActiveSession(EtwSessionName)?.Stop(); }
        catch { }

        using var session = new TraceEventSession(EtwSessionName);

        // Enable two kernel providers:
        //   FileIOInit   → FileIOCreate event (file opened by a process)
        //   NetworkTCPIP → TcpIpSend event    (TCP packet sent by a process)
        session.EnableKernelProvider(
            KernelTraceEventParser.Keywords.FileIOInit |
            KernelTraceEventParser.Keywords.NetworkTCPIP
        );

        var parser = session.Source.Kernel;

        // ── ETW subscriptions ─────────────────────────────────────────────
        parser.FileIOCreate  += OnFileCreate;
        parser.TcpIpSend     += OnTcpSend;
        parser.TcpIpSendIPV6 += OnTcpSendV6;

        // Stop the session when the service is told to shut down.
        stopping.Register(() =>
        {
            _log.LogInformation("Stopping ETW session.");
            session.Stop();
        });

        // Run the alert-check loop as a background task.
        var alertTask = Task.Run(() => AlertCheckLoopAsync(stopping), stopping);

        // session.Source.Process() blocks on this thread until session.Stop() is called.
        await Task.Run(() => session.Source.Process(), stopping).ConfigureAwait(false);

        // Wait for the alert-check loop to finish its current cycle.
        // AlertCheckLoopAsync now catches OperationCanceledException internally
        // so this await won't throw — the stop log below always runs.
        try { await alertTask.ConfigureAwait(false); } catch (OperationCanceledException) { }

        _alert.WriteInfo("LARGE_UPLOAD_MONITOR_STOPPED | reason=service_stop_requested");
        _log.LogInformation("LargeUploadMonitor stopped.");
    }

    // ─────────────────────────────────────────────────────────────────────
    //  ETW event handlers
    // ─────────────────────────────────────────────────────────────────────

    private void OnFileCreate(FileIOCreateTraceData data)
    {
        try
        {
            if (data.ProcessID <= 0) return;

            // Process name in ETW kernel events is the image name WITHOUT .exe
            string procExe = NormaliseProcName(data.ProcessName);
            if (!UploadCapable.Contains(procExe)) return;

            // ETW kernel file paths use NT device notation: \Device\HarddiskVolumeX\...
            // Convert to Win32 path: C:\...
            string win32 = DeviceToWin32(data.FileName);
            if (string.IsNullOrWhiteSpace(win32)) return;

            string lower = win32.ToLowerInvariant();

            // ── Path filters ──────────────────────────────────────────────
            // 1. Skip Windows system directories and Program Files.
            if (SystemStartsWith.Any(p => lower.StartsWith(p))) return;

            // 2. Skip ALL AppData — that's Chrome's cache, Firefox profile, etc.
            //    AppData files are never the file a user is uploading.
            if (lower.Contains(AppDataMarker)) return;

            // ── Extension filter ──────────────────────────────────────────
            string ext = Path.GetExtension(win32);
            if (!UploadExtensions.Contains(ext)) return;

            // ── Prefer user-space paths but don't REQUIRE them ────────────
            // If the extension is upload-worthy AND not in a system/app path,
            // record it regardless of whether it's in Downloads/Desktop/etc.
            // This catches files on D:\ drives, network shares, USB drives, etc.
            bool isUserPath = UserPathHints.Any(h => lower.Contains(h));

            // For non-user paths (e.g. D:\Projects\car.exe), only record
            // if the file has an upload-worthy extension (already filtered above).
            // For user paths, always record.
            _ = isUserPath; // both branches record — condition was informational

            // ── Get actual file size from the filesystem ──────────────────
            // This is one of the two key ETW advantages:
            // we get the size AT OPEN TIME, before any upload, exactly.
            long sizeBytes = 0;
            try { sizeBytes = new FileInfo(win32).Length; }
            catch { /* File might be locked — size stays 0, will fall back to delta */ }

            var record = new FileRecord(
                Timestamp:  DateTime.UtcNow,
                FullPath:   win32,
                FileName:   Path.GetFileName(win32),
                Extension:  ext,
                SizeBytes:  sizeBytes
            );

            // For subprocesses ex: All chrome.exe subprocesses (renderer, network, GPU…) share "chrome.exe".
            _filesByProc.AddOrUpdate(
                procExe,
                _ => new List<FileRecord> { record },
                (_, lst) => { lock (lst) { lst.Add(record); } return lst; }
            );
        }
        catch { /* Never let an ETW callback throw — it crashes the session */ }
    }

    private void OnTcpSend(TcpIpSendTraceData data)
    {
        RecordSend(data.ProcessID, data.size, data.daddr.ToString(), data.dport);
    }

    private void OnTcpSendV6(TcpIpV6SendTraceData data)
    {
        RecordSend(data.ProcessID, data.size, data.daddr.ToString(), data.dport);
    }

    private void RecordSend(int pid, int bytes, string destIp, int destPort)
    {
        try
        {
            if (pid <= 0 || bytes <= 0) return;
            // Skip loopback — IPC is not an upload.
            if (destIp.StartsWith("127.") || destIp == "::1") return;

            var record = new NetRecord(DateTime.UtcNow, bytes, destIp, destPort);
            _net.AddOrUpdate(
                pid,
                _ => new List<NetRecord> { record },
                (_, lst) => { lock (lst) { lst.Add(record); } return lst; }
            );
        }
        catch { }
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Alert-check loop  (runs every CheckIntervalMs on its own task)
    // ─────────────────────────────────────────────────────────────────────

    private async Task AlertCheckLoopAsync(CancellationToken stopping)
    {
        while (!stopping.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(CheckIntervalMs, stopping).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown — exit the loop cleanly without propagating.
                // If we let this propagate, 'await alertTask' in ExecuteAsync throws
                // and the LARGE_UPLOAD_MONITOR_STOPPED log never gets written.
                break;
            }

            try
            {
                PruneOldRecords();
                CheckForAlerts();
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "AlertCheckLoop error");
            }
        }
    }

    private void CheckForAlerts()
    {
        var now        = DateTime.UtcNow;
        var netCutoff  = now - TimeSpan.FromSeconds(WindowSec);
        var fileCutoff = now - TimeSpan.FromSeconds(FileCacheSec);

        foreach (var (pid, netList) in _net)
        {
            // ── Resolve process name first (needed for file lookup + cooldown) ──
            string procName;
            try
            {
                using var proc = Process.GetProcessById(pid);
                procName = NormaliseProcName(proc.ProcessName);
            }
            catch
            {
                // Process already exited — still want to fire the alert.
                // Use "exited.exe" as fallback; it won't match UploadCapable
                // so we only alert if a file record was found for it earlier.
                procName = "exited.exe";
            }

            // ── Cooldown: per process NAME, not per PID ───────────────────────
            // Using process name means all chrome.exe subprocesses share one cooldown.
            // Prevents duplicate alerts when multiple Chrome PIDs all send data
            // for the same upload (renderer + network service both counted).
            if (_alerted.TryGetValue(procName, out var lastAlert) &&
                (now - lastAlert).TotalSeconds < CooldownSec)
                continue;

            // ── Sum per-PID bytes in the rolling window ───────────────────────
            // Exact per-PID bytes — not system-wide. This is the ETW advantage.
            long totalBytes = 0;
            var  dests      = new HashSet<string>();

            lock (netList)
            {
                foreach (var r in netList)
                {
                    if (r.Timestamp < netCutoff) continue;
                    totalBytes += r.Bytes;
                    if (dests.Count < MaxDestinations)
                        dests.Add($"{r.DestIp}:{r.DestPort}");
                }
            }

            if (totalBytes < ThresholdBytes) continue;

            // ── Find the best upload file for this PROCESS NAME ───────────────
            // Example timeline:
            //   T=0  Chrome opens UploadFile.exe → stored in cache
            //   T=5  Alert fires, _alerted["chrome.exe"] = T=5
            //   T=65 New upload: Chrome opens UploadFile.exe (10.00 MB)
            //   T=70 Second alert check: filter by r.Timestamp > T=5
            //        → LargeUploadMonitor.exe (opened at T=0) EXCLUDED ✓
            //        → UploadFile.exe (opened at T=65) INCLUDED ✓
            FileRecord? fileRec = null;
            if (_filesByProc.TryGetValue(procName, out var fileList))
            {
                // Read the last alert time BEFORE we enter the lock
                lock (fileList)
                {
                    fileRec = fileList
                        .Where(r => r.Timestamp >= fileCutoff)
                        // Only files opened AFTER the previous alert for this process.
                        .Where(r => !_alerted.TryGetValue(procName, out var la)
                                    || r.Timestamp > la)
                        // Most recent file first — If not given then largest will be considered
                        .OrderByDescending(r => r.Timestamp)
                        .FirstOrDefault();
                }
            }

            // ── Alert gate: two-tier process classification ────────────────────
            //
            // HIGH-RISK CLI tools (curl, python, powershell…):
            //   Alert even with filename=Unknown. A script sending 50 MB out via
            //   curl is suspicious regardless of whether we can name the file.
            //
            // Browsers / cloud sync / comms (chrome, onedrive, teams…):
            //   REQUIRE a filename. Without one, this is background traffic:
            //     • YouTube / Netflix video buffering
            //     • Google Drive / OneDrive background sync
            //     • Chrome extension auto-updates
            //     • Google telemetry / crash reports
            //   These are NOT user-initiated uploads. Alerting on them is noise.
            //   The false positives (uploaded_mb=49-70, filename=Unknown) in the
            //   logs were exactly this: Chrome background traffic with no file opened.
            bool isHighRisk = HighRiskCapable.Contains(procName);
            if (fileRec == null && !isHighRisk)
            {
                _log.LogDebug(
                    "Skipped PID={Pid} ({Proc}) — {Mb:F1} MB sent but no upload file found. " +
                    "Likely background traffic (streaming/sync).",
                    pid, procName, totalBytes / (1024.0 * 1024.0));
                continue;
            }

            if (!UploadCapable.Contains(procName) && fileRec == null)
                continue;

            // ── Fire the alert ────────────────────────────────────────────────
            _alert.WriteAlert(
                pid:           pid,
                procName:      procName,
                filename:      fileRec?.FileName  ?? "Unknown",
                filetype:      fileRec?.Extension ?? "Unknown",
                destination:   string.Join(",", dests),
                deltaBytes:    totalBytes,
                fileSizeBytes: fileRec?.SizeBytes ?? 0,
                thresholdMb:   ThresholdMb
            );

            // Cooldown keyed by process name — blocks all Chrome subprocesses
            _alerted[procName] = now;

            // Clear this PID's network accumulator after firing.
            _net.TryRemove(pid, out _);

            _log.LogInformation(
                "Alert | PID={Pid} | proc={Proc} | file={File} | bytes={Bytes}",
                pid, procName, fileRec?.FileName ?? "Unknown", totalBytes);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Record pruning  (called every check cycle)
    // ─────────────────────────────────────────────────────────────────────

    private void PruneOldRecords()
    {
        var fileCutoff    = DateTime.UtcNow - TimeSpan.FromSeconds(FileCacheSec * 2);
        var netCutoff     = DateTime.UtcNow - TimeSpan.FromSeconds(WindowSec    * 3);
        var cooldownCutoff = DateTime.UtcNow - TimeSpan.FromMinutes(10);

        foreach (var (procName, lst) in _filesByProc)
        {
            lock (lst) { lst.RemoveAll(r => r.Timestamp < fileCutoff); }
            if (lst.Count == 0) _filesByProc.TryRemove(procName, out _);
        }

        foreach (var (pid, lst) in _net)
        {
            lock (lst) { lst.RemoveAll(r => r.Timestamp < netCutoff); }
            if (lst.Count == 0) _net.TryRemove(pid, out _);
        }

        foreach (var procName in _alerted.Keys.ToList())
        {
            if (_alerted.TryGetValue(procName, out var t) && t < cooldownCutoff)
                _alerted.TryRemove(procName, out _);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Device path → Win32 path conversion
    //
    //  ETW kernel events report file paths in NT device notation:
    //    \Device\HarddiskVolume3\Users\chirag\Downloads\car.exe
    //  We convert to Win32:
    //    C:\Users\chirag\Downloads\car.exe
    //
    //  The map is built once lazily using QueryDosDevice for each drive letter.
    // ─────────────────────────────────────────────────────────────────────

    private static readonly Lazy<Dictionary<string, string>> _driveMap =
        new(BuildDriveMap, LazyThreadSafetyMode.ExecutionAndPublication);

    private static Dictionary<string, string> BuildDriveMap()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var buf = new StringBuilder(512);

        foreach (var drive in DriveInfo.GetDrives())
        {
            string letter = drive.Name.TrimEnd('\\');   // "C:"
            buf.Clear();
            if (NativeMethods.QueryDosDevice(letter, buf, (uint)buf.Capacity) > 0)
                map[buf.ToString()] = letter;
        }
        return map;
    }

    private static string DeviceToWin32(string devicePath)
    {
        if (string.IsNullOrWhiteSpace(devicePath)) return string.Empty;

        foreach (var (device, letter) in _driveMap.Value)
        {
            if (devicePath.StartsWith(device, StringComparison.OrdinalIgnoreCase))
                return letter + devicePath[device.Length..];
        }

        // Couldn't map — return original (it's still usable for the filename)
        return devicePath;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Utility
    // ─────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Normalise an ETW process name to "name.exe" format.
    /// Kernel ETW events sometimes omit the .exe extension.
    /// </summary>
    private static string NormaliseProcName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "unknown.exe";
        return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? name
            : name + ".exe";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  P/Invoke
// ─────────────────────────────────────────────────────────────────────────────
internal static class NativeMethods
{
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    internal static extern uint QueryDosDevice(
        string            lpDeviceName,
        StringBuilder     lpTargetPath,
        uint              ucchMax);
}
