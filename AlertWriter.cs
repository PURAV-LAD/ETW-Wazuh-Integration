using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;

namespace LargeUploadMonitor;

/// <summary>
/// Writes structured LARGE_UPLOAD_DETECTED alerts to:
///   1. C:\LargeUploadMonitor\monitor.log  (Wazuh agent reads via localfile)
///   2. Windows Application Event Log       (Wazuh agent reads by default)
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AlertWriter
{
    // ── Config ────────────────────────────────────────────────────────────
    public const string LogDir  = @"C:\LargeUploadMonitor";
    public const string LogFile = @"C:\LargeUploadMonitor\monitor.log";

    private const string EventSource    = "LargeUploadMonitor";
    private const string EventLogName   = "Application";
    private const int    EventIdAlert   = 9001;
    private const int    EventIdInfo    = 9000;
    private const long   MaxLogBytes    = 5L * 1024 * 1024;   // 5 MB — then rotate
    private const int    RotationCount  = 3;

    private static readonly object _fileLock = new();

    // ─────────────────────────────────────────────────────────────────────
    public AlertWriter()
    {
        Directory.CreateDirectory(LogDir);
        EnsureEventSource();
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Public API
    // ─────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Write one LARGE_UPLOAD_DETECTED alert.
    /// <paramref name="fileSizeBytes"/> = actual file size from the filesystem.
    /// <paramref name="deltaBytes"/>    = exact per-PID TCP bytes sent (from ETW).
    /// report whichever is > 0: file size if known, else network delta.
    /// </summary>
    public void WriteAlert(
        int    pid,
        string procName,
        string filename,
        string filetype,
        string destination,
        long   deltaBytes,
        long   fileSizeBytes,
        int    thresholdMb)
    {
        // Use actual file size when known — fix for "wrong size" issue.
        // deltaBytes is always correct too (per-PID ETW), but file size is
        double reportMb = fileSizeBytes > 0
            ? fileSizeBytes / (1024.0 * 1024.0)
            : deltaBytes    / (1024.0 * 1024.0);

        string safe_filename = (filename ?? "Unknown").Replace(' ', '_').Replace('|', '-');
        string safe_filetype = (filetype ?? "Unknown").Replace(' ', '_').Replace('|', '-');

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

    public void WriteInfo(string message)
    {
        AppendLogLine(message, "INFO");
        WriteEventLog(message, EventIdInfo, EventLogEntryType.Information);
    }

    public void WriteError(string message)
    {
        AppendLogLine(message, "ERROR");
        WriteEventLog(message, EventIdInfo, EventLogEntryType.Error);
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Internals
    // ─────────────────────────────────────────────────────────────────────

    private static void AppendLogLine(string message, string level)
    {
        string line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{level}] {message}";

        lock (_fileLock)
        {
            try
            {
                RotateIfNeeded();
                File.AppendAllText(LogFile, line + Environment.NewLine, Encoding.UTF8);
            }
            catch { }
        }
    }

    private static void RotateIfNeeded()
    {
        if (!File.Exists(LogFile)) return;
        if (new FileInfo(LogFile).Length < MaxLogBytes) return;

        // Shift .log → .1, .1 → .2, etc.  Drop the oldest.
        for (int i = RotationCount - 1; i >= 1; i--)
        {
            string src  = LogFile + "." + i;
            string dst  = LogFile + "." + (i + 1);
            if (File.Exists(src)) File.Move(src, dst, overwrite: true);
        }
        File.Move(LogFile, LogFile + ".1", overwrite: true);
    }

    private static void WriteEventLog(string message, int eventId, EventLogEntryType type)
    {
        try
        {
            EventLog.WriteEntry(EventSource, message, type, eventId);
        }
        catch {}
    }

    private static void EnsureEventSource()
    {
        try
        {
            if (!EventLog.SourceExists(EventSource))
                EventLog.CreateEventSource(EventSource, EventLogName);
        }
        catch { }
    }
}
