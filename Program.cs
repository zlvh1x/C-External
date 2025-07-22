using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace YourNameSpace
{
    internal class Program
    {
        public class offsets
        {
            public static readonly ulong FakeDataModelPointer = 0x6833728;
            public static readonly ulong FakeDataModelToDataModel = 0x1C0;
            public static readonly ulong LocalPlayer = 0x128;
            public static readonly ulong ModelInstance = 0x340;
            public static readonly ulong WalkSpeed = 0x1DC;
            public static readonly ulong JumpPower = 0x1B8;
            public static readonly ulong WalkSpeedCheck = 0x3B8;
            public static readonly ulong Children = 0x80;
            public static readonly ulong ChildrenEnd = 0x8;
            public static readonly ulong Name = 0x78;
            public static readonly ulong ClassDescriptor = 0x18;
            public static readonly ulong ClassDescriptorToName = 0x8;
        }

        public class Mem
        {
            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesWritten);

            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool CloseHandle(IntPtr hObject);

            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
            public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool Module32FirstW(IntPtr hSnapshot, ref MODULEENTRY32W lpme);

            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool Module32NextW(IntPtr hSnapshot, ref MODULEENTRY32W lpme);

            public const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
            public const uint TH32CS_SNAPPROCESS = 0x00000002;
            public const uint TH32CS_SNAPMODULE = 0x00000008;
            public const uint TH32CS_SNAPMODULE32 = 0x00000010;

            [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
            public struct PROCESSENTRY32W
            {
                public uint dwSize;
                public uint cntUsage;
                public uint th32ProcessID;
                public IntPtr th32DefaultHeapID;
                public uint th32ModuleID;
                public uint cntThreads;
                public uint th32ParentProcessID;
                public int pcPriClassBase;
                public uint dwFlags;
                [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 260)]
                public string szExeFile;
            }

            [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
            public struct MODULEENTRY32W
            {
                public uint dwSize;
                public uint th32ModuleID;
                public uint th32ProcessID;
                public uint GlblcntUsage;
                public uint ProccntUsage;
                public IntPtr modBaseAddr;
                public uint modBaseSize;
                public IntPtr hModule;
                [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 256)]
                public string szModule;
                [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 260)]
                public string szExePath;
            }

            // Leer memoria genérico
            public static T Read<T>(IntPtr handle, IntPtr address) where T : struct
            {
                int size = System.Runtime.InteropServices.Marshal.SizeOf(typeof(T));
                byte[] buffer = new byte[size];
                int bytesRead;
                ReadProcessMemory(handle, address, buffer, size, out bytesRead);
                var handleGC = System.Runtime.InteropServices.GCHandle.Alloc(buffer, System.Runtime.InteropServices.GCHandleType.Pinned);
                T result = (T)System.Runtime.InteropServices.Marshal.PtrToStructure(handleGC.AddrOfPinnedObject(), typeof(T));
                handleGC.Free();
                return result;
            }

            public static bool Write<T>(IntPtr handle, IntPtr address, T value) where T : struct
            {
                int size = System.Runtime.InteropServices.Marshal.SizeOf(typeof(T));
                byte[] buffer = new byte[size];
                IntPtr ptr = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
                System.Runtime.InteropServices.Marshal.StructureToPtr(value, ptr, true);
                System.Runtime.InteropServices.Marshal.Copy(ptr, buffer, 0, size);
                System.Runtime.InteropServices.Marshal.FreeHGlobal(ptr);
                int bytesWritten;
                return WriteProcessMemory(handle, address, buffer, size, out bytesWritten);
            }

            public static uint GetProcId(string procName)
            {
                uint pid = 0;
                IntPtr hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                PROCESSENTRY32W entry = new PROCESSENTRY32W();
                entry.dwSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(PROCESSENTRY32W));
                if (Process32FirstW(hSnap, ref entry))
                {
                    do
                    {
                        if (string.Equals(entry.szExeFile, procName, StringComparison.OrdinalIgnoreCase))
                        {
                            pid = entry.th32ProcessID;
                            break;
                        }
                    } while (Process32NextW(hSnap, ref entry));
                }
                CloseHandle(hSnap);
                return pid;
            }

            public static ulong GetModuleBaseAddy(uint procId, string modName)
            {
                ulong baseAddr = 0;
                IntPtr hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
                MODULEENTRY32W modEntry = new MODULEENTRY32W();
                modEntry.dwSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(MODULEENTRY32W));
                if (Module32FirstW(hSnap, ref modEntry))
                {
                    do
                    {
                        if (string.Equals(modEntry.szModule, modName, StringComparison.OrdinalIgnoreCase))
                        {
                            baseAddr = (ulong)modEntry.modBaseAddr;
                            break;
                        }
                    } while (Module32NextW(hSnap, ref modEntry));
                }
                CloseHandle(hSnap);
                return baseAddr;
            }
        }

        public class Roblox
        {
            public static string GetName(IntPtr process, ulong addy)
            {
                ulong namePointer = Mem.Read<ulong>(process, (IntPtr)(addy + offsets.Name));
                string name = string.Empty;

                int strLen = Mem.Read<int>(process, (IntPtr)(namePointer + 0x10));
                if (strLen >= 16)
                {
                    ulong namePointer2 = Mem.Read<ulong>(process, (IntPtr)namePointer);
                    char c;
                    while ((c = Mem.Read<char>(process, (IntPtr)namePointer2)) != '\0')
                    {
                        name += c;
                        namePointer2++;
                    }
                }
                else
                {
                    byte[] buffer = new byte[16];
                    int bytesRead;
                    Mem.ReadProcessMemory(process, (IntPtr)namePointer, buffer, 16, out bytesRead);
                    name = System.Text.Encoding.UTF8.GetString(buffer).Split('\0')[0];
                }
                return name;
            }

            public static string GetClassName(IntPtr process, ulong addy)
            {
                ulong classDescriptor = Mem.Read<ulong>(process, (IntPtr)(addy + offsets.ClassDescriptor));
                ulong classDescriptorToName = Mem.Read<ulong>(process, (IntPtr)(classDescriptor + offsets.ClassDescriptorToName));
                if (classDescriptorToName == 0)
                    return "Unknown";

                string name = string.Empty;
                int strLen = Mem.Read<int>(process, (IntPtr)(classDescriptorToName + 0x10));
                if (strLen >= 16)
                {
                    ulong namePointer2 = Mem.Read<ulong>(process, (IntPtr)classDescriptorToName);
                    char c;
                    while ((c = Mem.Read<char>(process, (IntPtr)namePointer2)) != '\0')
                    {
                        name += c;
                        namePointer2++;
                    }
                }
                else
                {
                    byte[] buffer = new byte[16];
                    int bytesRead;
                    Mem.ReadProcessMemory(process, (IntPtr)classDescriptorToName, buffer, 16, out bytesRead);
                    name = System.Text.Encoding.UTF8.GetString(buffer).Split('\0')[0];
                }
                return name;
            }

            public static List<ulong> GetChildren(IntPtr process, ulong addy)
            {
                List<ulong> childrens = new List<ulong>();
                ulong children = Mem.Read<ulong>(process, (IntPtr)(addy + offsets.Children));
                ulong childrenEnd = Mem.Read<ulong>(process, (IntPtr)(children + offsets.ChildrenEnd));

                for (ulong child = Mem.Read<ulong>(process, (IntPtr)children); child < childrenEnd; child += 0x10)
                {
                    childrens.Add(Mem.Read<ulong>(process, (IntPtr)child));
                }
                return childrens;
            }

            public static ulong FindFirstChildByName(IntPtr process, ulong addy, string name)
            {
                foreach (var child in GetChildren(process, addy))
                {
                    if (GetName(process, child) == name)
                        return child;
                }
                return 0;
            }
        }

        static void Main(string[] args)
        {
            var pid = Mem.GetProcId("RobloxPlayerBeta.exe");
            if (pid == 0) { Console.WriteLine("Not found"); return; }
            var proc = Mem.OpenProcess(0x0010 | 0x0020 | 0x0008, false, pid);
            if (proc == IntPtr.Zero) return;
            var baseAddr = Mem.GetModuleBaseAddy(pid, "RobloxPlayerBeta.exe");
            if (baseAddr == 0) { Mem.CloseHandle(proc); return; }
            Console.WriteLine($"Module Base Address: 0x{baseAddr:X}");

            var fakeDm = Mem.Read<ulong>(proc, (IntPtr)(baseAddr + offsets.FakeDataModelPointer));
            var dm = Mem.Read<ulong>(proc, (IntPtr)(fakeDm + offsets.FakeDataModelToDataModel));
            Console.WriteLine($"DataModel Address: 0x{dm:X}");
            var players = Roblox.FindFirstChildByName(proc, dm, "Players");
            var local = Mem.Read<ulong>(proc, (IntPtr)(players + offsets.LocalPlayer));
            var charac = Mem.Read<ulong>(proc, (IntPtr)(local + offsets.ModelInstance));
            var humanoid = Roblox.FindFirstChildByName(proc, charac, "Humanoid");
            if (humanoid == 0) { Mem.CloseHandle(proc); return; }

            float ws = Mem.Read<float>(proc, (IntPtr)(humanoid + offsets.WalkSpeed));
            float jp = Mem.Read<float>(proc, (IntPtr)(humanoid + offsets.JumpPower));
            Console.WriteLine($"Current WalkSpeed: {ws}, Current JumpPower: {jp}");

            Mem.Write(proc, (IntPtr)(humanoid + offsets.WalkSpeed), 200f);
            Mem.Write(proc, (IntPtr)(humanoid + offsets.WalkSpeedCheck), 200f);
            Mem.Write(proc, (IntPtr)(humanoid + offsets.JumpPower), 200f);
            System.Threading.Thread.Sleep(1200);

            ws = Mem.Read<float>(proc, (IntPtr)(humanoid + offsets.WalkSpeed));
            jp = Mem.Read<float>(proc, (IntPtr)(humanoid + offsets.JumpPower));
            Console.WriteLine($"New WalkSpeed: {ws}, New JumpPower: {jp}");
            Mem.CloseHandle(proc);
        }

        static ulong GetHumanoidPtr(IntPtr process, ulong baseAddr)
        {
            var fakeDm = Mem.Read<ulong>(process, (IntPtr)(baseAddr + offsets.FakeDataModelPointer));
            if (fakeDm == 0) return 0;
            var dm = Mem.Read<ulong>(process, (IntPtr)(fakeDm + offsets.FakeDataModelToDataModel));
            if (dm == 0) return 0;
            var players = Roblox.FindFirstChildByName(process, dm, "Players");
            var localPlayer = Mem.Read<ulong>(process, (IntPtr)(players + offsets.LocalPlayer));
            var character = Mem.Read<ulong>(process, (IntPtr)(localPlayer + offsets.ModelInstance));
            return Roblox.FindFirstChildByName(process, character, "Humanoid");
        }

        static void ShowValues(IntPtr process, ulong humanoid, string title)
        {
            float ws = Mem.Read<float>(process, (IntPtr)(humanoid + offsets.WalkSpeed));
            float jp = Mem.Read<float>(process, (IntPtr)(humanoid + offsets.JumpPower));
            Console.WriteLine($"{title} WalkSpeed: {ws}, JumpPower: {jp}");
        }

        static void SetValues(IntPtr process, ulong humanoid, float value)
        {
            Mem.Write(process, (IntPtr)(humanoid + offsets.WalkSpeed), value);
            Mem.Write(process, (IntPtr)(humanoid + offsets.WalkSpeedCheck), value);
            Mem.Write(process, (IntPtr)(humanoid + offsets.JumpPower), value);
        }
    }
}
