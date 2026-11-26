using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace HongAi.NativeBoundary {
    // The test executable can filter only its own exact executable identity.
    // There is deliberately no command that installs rules against customer apps yet.
    internal static class Native {
        [StructLayout(LayoutKind.Explicit, Size=8)] internal struct Union {
            [FieldOffset(0)] internal byte U8;
            [FieldOffset(0)] internal ushort U16;
            [FieldOffset(0)] internal uint U32;
            [FieldOffset(0)] internal IntPtr Ptr;
        }
        [StructLayout(LayoutKind.Sequential)] internal struct Value { internal uint Type; internal Union Data; }
        [StructLayout(LayoutKind.Sequential)] internal struct Blob { internal uint Size; internal IntPtr Data; }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] internal struct Display {
            [MarshalAs(UnmanagedType.LPWStr)] internal string Name;
            [MarshalAs(UnmanagedType.LPWStr)] internal string Description;
        }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] internal struct Session {
            internal Guid Key; internal Display Display; internal uint Flags; internal uint WaitMs;
            internal uint ProcessId; internal IntPtr Sid;
            [MarshalAs(UnmanagedType.LPWStr)] internal string UserName;
            internal int KernelMode;
        }
        [StructLayout(LayoutKind.Sequential)] internal struct Sublayer {
            internal Guid Key; internal Display Display; internal uint Flags; internal IntPtr Provider;
            internal Blob ProviderData; internal ushort Weight;
        }
        [StructLayout(LayoutKind.Sequential)] internal struct Condition {
            internal Guid Field; internal uint Match; internal Value Value;
        }
        [StructLayout(LayoutKind.Sequential)] internal struct Action { internal uint Type; internal Guid FilterType; }
        [StructLayout(LayoutKind.Explicit, Size=16)] internal struct Context { [FieldOffset(0)] internal ulong Raw; }
        [StructLayout(LayoutKind.Sequential)] internal struct Filter {
            internal Guid Key; internal Display Display; internal uint Flags; internal IntPtr Provider;
            internal Blob ProviderData; internal Guid Layer; internal Guid Sublayer;
            internal Value Weight; internal uint Count; internal IntPtr Conditions;
            internal Action Action; internal Context Context; internal IntPtr Reserved;
            internal ulong Id; internal Value EffectiveWeight;
        }
        internal static readonly Guid ConnectV4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
        internal static readonly Guid ConnectV6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
        internal static readonly Guid AppId = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
        internal static readonly Guid RemoteAddress = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
        internal static readonly Guid RemotePort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");
        internal static readonly Guid Protocol = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
        [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode)] internal static extern uint FwpmEngineOpen0(string server, uint auth, IntPtr identity, ref Session session, out IntPtr engine);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmEngineClose0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmTransactionCommit0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmTransactionAbort0(IntPtr engine);
        [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode)] internal static extern uint FwpmSubLayerAdd0(IntPtr engine, ref Sublayer sublayer, IntPtr sd);
        [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode)] internal static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr sd, out ulong id);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine, ref Guid key);
        [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode)] internal static extern uint FwpmGetAppIdFromFileName0(string filename, out IntPtr blob);
        [DllImport("fwpuclnt.dll")] internal static extern void FwpmFreeMemory0(ref IntPtr memory);
        internal static void Check(uint code, string stage) { if(code != 0) throw new Win32Exception(unchecked((int)code), stage+" error=0x"+code.ToString("X8")); }
    }

    internal sealed class SelfTestBoundary : IDisposable {
        private IntPtr engine;
        private readonly Guid sublayerKey;
        private readonly bool persistent;
        private readonly List<Guid> filterKeys = new List<Guid>();
        private static readonly Guid TestSublayer = new Guid("814b7c40-9a43-4c59-8c17-b3156cfbe8f5");
        private static readonly Guid[] TestFilters = new [] {
            new Guid("14404750-d4e1-48c7-9d0e-a3f4d30f5a01"), new Guid("14404750-d4e1-48c7-9d0e-a3f4d30f5a02"),
            new Guid("14404750-d4e1-48c7-9d0e-a3f4d30f5a03"), new Guid("14404750-d4e1-48c7-9d0e-a3f4d30f5a04")
        };
        internal SelfTestBoundary(string executable, ushort proxyPort, bool persist) {
            persistent=persist; sublayerKey=persist ? TestSublayer : Guid.NewGuid();
            string self = Process.GetCurrentProcess().MainModule.FileName;
            if(!String.Equals(Path.GetFullPath(executable), Path.GetFullPath(self), StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("SELF_TEST_EXACT_IDENTITY_ONLY");
            if(proxyPort < 1024) throw new ArgumentException("HIGH_LOOPBACK_PORT_REQUIRED");
            if(!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) throw new InvalidOperationException("ADMIN_REQUIRED_FOR_ISOLATED_WFP_SELF_TEST");
            Native.Session session = new Native.Session();
            session.Key = Guid.NewGuid(); session.Flags = persist ? 0U : 1U;
            session.Display.Name="HONG AI isolated WFP self-test"; session.WaitMs=3000;
            Native.Check(Native.FwpmEngineOpen0(null, 10, IntPtr.Zero, ref session, out engine),"open");
            bool transaction=false;
            IntPtr appId=IntPtr.Zero;
            try {
                Native.Check(Native.FwpmGetAppIdFromFileName0(self,out appId),"app-id");
                Native.Check(Native.FwpmTransactionBegin0(engine,0),"begin"); transaction=true;
                Native.Sublayer sub = new Native.Sublayer(); sub.Key=sublayerKey; sub.Weight=0x7000; sub.Flags=persist ? 1U : 0U;
                sub.Display.Name="HONG AI test binary only";
                Native.Check(Native.FwpmSubLayerAdd0(engine,ref sub,IntPtr.Zero),"sublayer");
                Native.Condition app = Condition(Native.AppId,0,12,appId,0);
                Add("block other IPv4",Native.ConnectV4,new[]{app,Condition(Native.RemoteAddress,10,3,IntPtr.Zero,0x7F000001)});
                Add("block other ports",Native.ConnectV4,new[]{app,Condition(Native.RemotePort,10,2,IntPtr.Zero,proxyPort)});
                Add("block non TCP",Native.ConnectV4,new[]{app,Condition(Native.Protocol,10,1,IntPtr.Zero,6)});
                Add("block IPv6",Native.ConnectV6,new[]{app});
                Native.Check(Native.FwpmTransactionCommit0(engine),"commit"); transaction=false;
            } catch {
                if(transaction) Native.FwpmTransactionAbort0(engine);
                Dispose(); throw;
            } finally { if(appId != IntPtr.Zero) Native.FwpmFreeMemory0(ref appId); }
        }
        private static Native.Condition Condition(Guid field,uint match,uint type,IntPtr pointer,uint value) {
            Native.Condition condition = new Native.Condition(); condition.Field=field; condition.Match=match; condition.Value.Type=type;
            if(type==12) condition.Value.Data.Ptr=pointer;
            else if(type==1) condition.Value.Data.U8=checked((byte)value);
            else if(type==2) condition.Value.Data.U16=checked((ushort)value);
            else condition.Value.Data.U32=value;
            return condition;
        }
        private void Add(string name,Guid layer,Native.Condition[] conditions) {
            if(conditions.Length == 0 || conditions[0].Field != Native.AppId) throw new InvalidOperationException("UNSCOPED_FILTER_FORBIDDEN");
            int size=Marshal.SizeOf(typeof(Native.Condition)); IntPtr memory=Marshal.AllocHGlobal(size*conditions.Length);
            try {
                for(int i=0;i<conditions.Length;i++) Marshal.StructureToPtr(conditions[i],IntPtr.Add(memory,i*size),false);
                Native.Filter filter = new Native.Filter(); filter.Key=persistent ? TestFilters[filterKeys.Count] : Guid.NewGuid(); filter.Flags=persistent ? 1U : 0U;
                filter.Display.Name="HONGAI self-test "+name;
                filter.Layer=layer; filter.Sublayer=sublayerKey; filter.Count=(uint)conditions.Length; filter.Conditions=memory;
                filter.Action.Type=0x1001; // FWP_ACTION_BLOCK
                filter.Weight.Type=1; filter.Weight.Data.U8=15;
                ulong id; Native.Check(Native.FwpmFilterAdd0(engine,ref filter,IntPtr.Zero,out id),name);
                filterKeys.Add(filter.Key);
            } finally { Marshal.FreeHGlobal(memory); }
        }
        internal void CloseEngineRetainingSelfTestRules() {
            if(!persistent) throw new InvalidOperationException("PERSISTENT_TEST_ONLY");
            if(engine!=IntPtr.Zero) { Native.Check(Native.FwpmEngineClose0(engine),"close-test-controller"); engine=IntPtr.Zero; }
        }
        internal static void RollbackPersistentTest() {
            if(!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) throw new InvalidOperationException("ADMIN_REQUIRED_FOR_TEST_ROLLBACK");
            Native.Session session=new Native.Session(); session.Key=Guid.NewGuid(); session.Display.Name="HONGAI exact test-rule recovery";
            IntPtr recovery; Native.Check(Native.FwpmEngineOpen0(null,10,IntPtr.Zero,ref session,out recovery),"open-recovery");
            bool transaction=false;
            try {
                Native.Check(Native.FwpmTransactionBegin0(recovery,0),"begin-recovery"); transaction=true;
                foreach(Guid item in TestFilters) {
                    Guid key=item; uint code=Native.FwpmFilterDeleteByKey0(recovery,ref key);
                    if(code!=0 && code!=0x80320003) Native.Check(code,"delete-own-test-filter");
                }
                Guid sub=TestSublayer; uint subCode=Native.FwpmSubLayerDeleteByKey0(recovery,ref sub);
                if(subCode!=0 && subCode!=0x80320007) Native.Check(subCode,"delete-own-test-sublayer");
                Native.Check(Native.FwpmTransactionCommit0(recovery),"commit-recovery"); transaction=false;
            } finally { if(transaction) Native.FwpmTransactionAbort0(recovery); Native.FwpmEngineClose0(recovery); }
        }
        public void Dispose() {
            if(engine != IntPtr.Zero) { Native.FwpmEngineClose0(engine); engine=IntPtr.Zero; }
            if(persistent) RollbackPersistentTest();
        }
    }

    internal static class Program {
        private static int checks;
        private static void Assert(bool condition,string label) {
            if(!condition) throw new InvalidOperationException("ASSERT_FAILED "+label);
            checks++; Console.WriteLine("PASS "+label);
        }
        private static bool Connect(IPAddress address,int port) {
            using(TcpClient client=new TcpClient(address.AddressFamily)) {
                try { var task=client.ConnectAsync(address,port); return task.Wait(1800) && client.Connected; }
                catch { return false; }
            }
        }
        private static int AbiTest() {
            Assert(IntPtr.Size==8,"x64 runtime");
            Assert(Marshal.SizeOf(typeof(Native.Value))==16,"FWP_VALUE0 size");
            Assert(Marshal.SizeOf(typeof(Native.Blob))==16,"FWP_BYTE_BLOB size");
            Assert(Marshal.SizeOf(typeof(Native.Condition))==40,"FWPM_FILTER_CONDITION0 size");
            Assert(Marshal.SizeOf(typeof(Native.Filter))==200,"FWPM_FILTER0 size");
            Assert(Marshal.SizeOf(typeof(Native.Sublayer))==72,"FWPM_SUBLAYER0 size");
            Assert(Marshal.SizeOf(typeof(Native.Session))==72,"FWPM_SESSION0 size");
            Assert(Marshal.OffsetOf(typeof(Native.Filter),"Conditions").ToInt32()==120,"condition array offset");
            Assert(Marshal.OffsetOf(typeof(Native.Filter),"Action").ToInt32()==128,"action offset");
            Assert(Marshal.OffsetOf(typeof(Native.Filter),"EffectiveWeight").ToInt32()==184,"effective weight offset");
            IntPtr appId; Native.Check(Native.FwpmGetAppIdFromFileName0(Process.GetCurrentProcess().MainModule.FileName,out appId),"read-only app-id");
            try { Assert(appId!=IntPtr.Zero,"Windows resolves exact application identity"); }
            finally { Native.FwpmFreeMemory0(ref appId); }
            Console.WriteLine("ABI_TEST_PASSED checks="+checks+" network_changes=0"); return 0;
        }
        private static int KernelTest(bool persistent) {
            if(!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) {
                Console.WriteLine("BLOCKED_ADMIN_REQUIRED network_changes=0"); return 77;
            }
            TcpListener allowed=new TcpListener(IPAddress.Loopback,0);
            TcpListener other=new TcpListener(IPAddress.Loopback,0);
            TcpListener address=null; TcpListener ipv6=null;
            try {
                allowed.Start(); other.Start();
                int port=((IPEndPoint)allowed.LocalEndpoint).Port;
                int otherPort=((IPEndPoint)other.LocalEndpoint).Port;
                address=new TcpListener(IPAddress.Parse("127.0.0.2"),port); address.Start();
                if(Socket.OSSupportsIPv6) { ipv6=new TcpListener(IPAddress.IPv6Loopback,port); ipv6.Server.DualMode=false; ipv6.Start(); }
                Assert(Connect(IPAddress.Loopback,port),"baseline selected loopback");
                Assert(Connect(IPAddress.Loopback,otherPort),"baseline alternate loopback port");
                Assert(Connect(IPAddress.Parse("127.0.0.2"),port),"baseline alternate loopback address");
                if(ipv6!=null) Assert(Connect(IPAddress.IPv6Loopback,port),"baseline IPv6 loopback");
                using(SelfTestBoundary boundary=new SelfTestBoundary(Process.GetCurrentProcess().MainModule.FileName,checked((ushort)port),persistent)) {
                    Assert(Connect(IPAddress.Loopback,port),"selected TCP proxy remains reachable");
                    Assert(!Connect(IPAddress.Loopback,otherPort),"other port blocked in kernel");
                    Assert(!Connect(IPAddress.Parse("127.0.0.2"),port),"other address blocked in kernel");
                    if(ipv6!=null) Assert(!Connect(IPAddress.IPv6Loopback,port),"IPv6 bypass blocked in kernel");
                    if(persistent) {
                        boundary.CloseEngineRetainingSelfTestRules();
                        Assert(Connect(IPAddress.Loopback,port),"pinned loopback remains reachable after controller engine closes");
                        Assert(!Connect(IPAddress.Loopback,otherPort),"persistent block survives controller engine closure");
                        Assert(!Connect(IPAddress.Parse("127.0.0.2"),port),"persistent address block survives controller engine closure");
                    }
                    allowed.Stop(); Assert(!Connect(IPAddress.Loopback,port),"proxy stopped gives no connection");
                    Assert(!Connect(IPAddress.Loopback,otherPort),"proxy loss never opens alternate route");
                }
                Assert(Connect(IPAddress.Loopback,otherPort),"exact self-test rules removed on session close");
                Console.WriteLine("KERNEL_SELFTEST_PASSED checks="+checks+" persistent_test="+persistent+" scope=own_test_binary customer_acceptance=false"); return 0;
            } finally {
                allowed.Stop(); other.Stop(); if(address!=null) address.Stop(); if(ipv6!=null) ipv6.Stop();
            }
        }
        internal static int Main(string[] args) {
            try {
                if(args.Length==1 && args[0]=="--abi-test") return AbiTest();
                if(args.Length==1 && args[0]=="--self-test") return KernelTest(false);
                if(args.Length==1 && args[0]=="--persistent-self-test") return KernelTest(true);
                if(args.Length==1 && args[0]=="--rollback-self-test") { SelfTestBoundary.RollbackPersistentTest(); Console.WriteLine("OWN_TEST_RULES_REMOVED"); return 0; }
                Console.WriteLine("HONG AI WFP development: --abi-test, --self-test, --persistent-self-test, --rollback-self-test. No customer install command exists."); return 64;
            } catch(Exception ex) { Console.Error.WriteLine(ex.Message); return 1; }
        }
    }
}
