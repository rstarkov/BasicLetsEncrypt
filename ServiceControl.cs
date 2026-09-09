using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace BasicLetsEncrypt;

/// <summary>Restarts Windows services via the Service Control Manager API.</summary>
static class ServiceControl
{
    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SERVICE_QUERY_STATUS = 0x0004;
    private const uint SERVICE_START = 0x0010;
    private const uint SERVICE_STOP = 0x0020;
    private const uint SERVICE_CONTROL_STOP = 0x0001;
    private const uint SERVICE_STOPPED = 1;
    private const uint SERVICE_RUNNING = 4;
    private const int ERROR_SERVICE_ALREADY_RUNNING = 1056;
    private const int ERROR_SERVICE_DOES_NOT_EXIST = 1060;
    private static readonly TimeSpan StateTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    ///     Stops the service if it is running, then starts it, retrying the start up to 3 times at 5 second intervals. Throws a
    ///     <see cref="ServiceControlException"/> if the service does not exist, does not stop, or does not start.</summary>
    public static void Restart(string serviceName)
    {
        using var manager = OpenSCManager(null, null, SC_MANAGER_CONNECT);
        if (manager.IsInvalid)
            throw new ServiceControlException($"Could not connect to the service control manager: {LastError()}");
        using var service = OpenService(manager, serviceName, SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP);
        if (service.IsInvalid)
        {
            if (Marshal.GetLastWin32Error() == ERROR_SERVICE_DOES_NOT_EXIST)
                throw new ServiceControlException($"Service \"{serviceName}\" does not exist.");
            throw new ServiceControlException($"Could not open service \"{serviceName}\": {LastError()}");
        }

        var state = QueryState(service);
        Console.WriteLine($"Service \"{serviceName}\" was {Describe(state)} before renewal.");
        if (state != SERVICE_STOPPED)
        {
            if (!ControlService(service, SERVICE_CONTROL_STOP, out _))
                throw new ServiceControlException($"Could not stop service \"{serviceName}\": {LastError()}");
            if (!WaitForState(service, SERVICE_STOPPED))
                throw new ServiceControlException($"Service \"{serviceName}\" did not stop within {StateTimeout.TotalSeconds} seconds.");
            Console.WriteLine($"Service \"{serviceName}\" stopped.");
        }

        for (int attempt = 1; ; attempt++)
        {
            var failure = TryStart(service);
            if (failure == null)
            {
                Console.WriteLine($"Service \"{serviceName}\" started.");
                return;
            }
            Console.WriteLine($"Attempt {attempt} of 3 to start service \"{serviceName}\" failed: {failure}");
            if (attempt == 3)
                throw new ServiceControlException($"Could not start service \"{serviceName}\" after 3 attempts.");
            Thread.Sleep(5000);
        }
    }

    /// <summary>Starts the service and waits for it to be running. Returns null on success, otherwise a description of the failure.</summary>
    private static string TryStart(SafeServiceHandle service)
    {
        if (!StartService(service, 0, null) && Marshal.GetLastWin32Error() != ERROR_SERVICE_ALREADY_RUNNING)
            return LastError();
        if (!WaitForState(service, SERVICE_RUNNING))
            return $"service is {Describe(QueryState(service))} after {StateTimeout.TotalSeconds} seconds";
        return null;
    }

    /// <summary>Polls the service until it reaches the state, or (when waiting for it to start) it stops again, or the timeout passes.</summary>
    private static bool WaitForState(SafeServiceHandle service, uint state)
    {
        var deadline = DateTime.UtcNow + StateTimeout;
        while (true)
        {
            var current = QueryState(service);
            if (current == state)
                return true;
            if (state == SERVICE_RUNNING && current == SERVICE_STOPPED)
                return false;
            if (DateTime.UtcNow >= deadline)
                return false;
            Thread.Sleep(500);
        }
    }

    private static uint QueryState(SafeServiceHandle service)
    {
        if (!QueryServiceStatus(service, out var status))
            throw new ServiceControlException($"Could not query the service status: {LastError()}");
        return status.dwCurrentState;
    }

    private static string Describe(uint state)
    {
        return state switch
        {
            1 => "stopped",
            2 => "starting",
            3 => "stopping",
            4 => "running",
            5 => "resuming",
            6 => "pausing",
            7 => "paused",
            _ => $"in state {state}",
        };
    }

    private static string LastError()
    {
        return new Win32Exception(Marshal.GetLastWin32Error()).Message;
    }

    private class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeServiceHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeServiceHandle OpenSCManager(string machineName, string databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeServiceHandle OpenService(SafeServiceHandle manager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatus(SafeServiceHandle service, out SERVICE_STATUS status);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ControlService(SafeServiceHandle service, uint control, out SERVICE_STATUS status);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool StartService(SafeServiceHandle service, uint argCount, string[] args);
}

class ServiceControlException : Exception
{
    public ServiceControlException(string message) : base(message) { }
}
