/*
 * Large Upload Monitor — Windows Service (C# ETW edition)
 * ========================================================
 * Uses Windows ETW (Event Tracing for Windows) kernel providers to detect
 * large file uploads in real time — NOT polling.
 *
 * WHY ETW instead of Python polling:
 *   FileIOCreate  → fires the instant Firefox opens car.exe for reading
 *   TcpIpSend     → fires for every TCP packet, per-PID bytes (not system-wide)
 *   Zero polling delay. Zero "file handle already closed" problem.
 *
 * ═══════════════════════════════════════════════════════════════════════
 *  BUILD (run once on any machine with .NET 8 SDK)
 * ═══════════════════════════════════════════════════════════════════════
 *  dotnet publish -c Release -r win-x64 --self-contained ^
 *      -p:PublishSingleFile=true ^
 *      -o C:\Build\LargeUploadMonitor
 *
 *  Output: C:\Build\LargeUploadMonitor\LargeUploadMonitor.exe  (~70 MB)
 *  No .NET runtime install needed on target machines.
 *
 * ═══════════════════════════════════════════════════════════════════════
 *  DEPLOY ON TARGET PC (as Administrator)
 * ═══════════════════════════════════════════════════════════════════════
 *  mkdir C:\LargeUploadMonitor
 *  copy LargeUploadMonitor.exe C:\LargeUploadMonitor\
 *  C:\LargeUploadMonitor\LargeUploadMonitor.exe install
 *  C:\LargeUploadMonitor\LargeUploadMonitor.exe start
 *
 *  Commands:
 *    install   Register as Windows service (auto-start, LocalSystem)
 *    start     Start the service
 *    stop      Stop the service
 *    restart   Stop then start
 *    remove    Stop and unregister the service
 *    status    Print current service state
 *
 * ═══════════════════════════════════════════════════════════════════════
 *  WAZUH AGENT CONFIG — add to ossec.conf on monitored machine
 * ═══════════════════════════════════════════════════════════════════════
 *  <localfile>
 *    <log_format>syslog</log_format>
 *    <location>C:\LargeUploadMonitor\monitor.log</location>
 *  </localfile>
 */

using System.Diagnostics;
using System.Runtime.Versioning;
using System.ServiceProcess;
using Microsoft.Extensions.Hosting.WindowsServices;
using LargeUploadMonitor;

[SupportedOSPlatform("windows")]
internal static class Program
{
    private const string ServiceName        = "LargeUploadMonitor";
    private const string ServiceDisplayName = "Large Upload Monitor (SOC)";
    private const string ServiceDescription = "Real-time upload detection via ETW kernel events.";

    static async Task<int> Main(string[] args)
    {
        // ── CLI commands (install / start / stop / restart / remove / status) ──
        if (args.Length > 0)
        {
            return HandleCliCommand(args[0].ToLowerInvariant());
        }

        // ── Service host ──────────────────────────────────────────────────────
        var builder = Host.CreateDefaultBuilder(args)
            .UseWindowsService(o => o.ServiceName = ServiceName)
            .ConfigureLogging(logging =>
            {
                logging.ClearProviders();
                // Only log to Event Log when running as a service;
                // console log is lost under SCM anyway.
                logging.AddEventLog(new Microsoft.Extensions.Logging.EventLog.EventLogSettings
                {
                    SourceName = ServiceName,
                    LogName    = "Application",
                });
            })
            .ConfigureServices((_, services) =>
            {
                services.AddSingleton<AlertWriter>();
                services.AddHostedService<MonitorWorker>();
            });

        await builder.Build().RunAsync();
        return 0;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  CLI helpers
    // ─────────────────────────────────────────────────────────────────────────

    private static int HandleCliCommand(string cmd)
    {
        string exePath = Environment.ProcessPath
            ?? Process.GetCurrentProcess().MainModule?.FileName
            ?? throw new InvalidOperationException("Cannot determine executable path.");

        switch (cmd)
        {
            case "install":
                Console.WriteLine($"[*] Installing service '{ServiceName}' ...");
                Sc($"create {ServiceName} " +
                   $"binpath=\"{exePath}\" " +
                   $"start=auto " +
                   $"obj=LocalSystem " +
                   $"displayname=\"{ServiceDisplayName}\"");
                Sc($"description {ServiceName} \"{ServiceDescription}\"");
                Console.WriteLine("[+] Installed. Run 'install start' to start it.");
                return 0;

            case "start":
                Console.WriteLine($"[*] Starting '{ServiceName}' ...");
                Sc($"start {ServiceName}");
                return 0;

            case "stop":
                Console.WriteLine($"[*] Stopping '{ServiceName}' ...");
                Sc($"stop {ServiceName}");
                return 0;

            case "restart":
                Console.WriteLine($"[*] Restarting '{ServiceName}' ...");
                Sc($"stop {ServiceName}");
                Thread.Sleep(2000);
                Sc($"start {ServiceName}");
                return 0;

            case "remove":
            case "uninstall":
                Console.WriteLine($"[*] Removing '{ServiceName}' ...");
                Sc($"stop {ServiceName}");
                Thread.Sleep(1500);
                Sc($"delete {ServiceName}");
                Console.WriteLine("[+] Removed.");
                return 0;

            case "status":
                try
                {
                    using var svc = new ServiceController(ServiceName);
                    Console.WriteLine($"Status: {svc.Status}");
                }
                catch
                {
                    Console.WriteLine("Service not found (not installed).");
                }
                return 0;

            default:
                Console.WriteLine($"Unknown command: {cmd}");
                Console.WriteLine("Commands: install | start | stop | restart | remove | status");
                return 1;
        }
    }

    private static void Sc(string arguments)
    {
        var p = Process.Start(new ProcessStartInfo("sc.exe", arguments)
        {
            UseShellExecute        = false,
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
        })!;
        p.WaitForExit();
        string output = p.StandardOutput.ReadToEnd().Trim();
        string error  = p.StandardError.ReadToEnd().Trim();
        if (!string.IsNullOrWhiteSpace(output)) Console.WriteLine(output);
        if (!string.IsNullOrWhiteSpace(error))  Console.WriteLine("[err] " + error);
    }
}
