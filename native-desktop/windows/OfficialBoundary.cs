using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;

namespace HongAi.NativeBoundary {
    public sealed class ProgramRecord { public string Path; public string Sha256; }
    public sealed class BoundaryJournal {
        public string Schema="hongai.official-executable-boundary.v1";
        public string Root; public int ProxyPort; public string Phase;
        public List<ProgramRecord> Programs;
        public bool CustomerAccepted=false;
    }

    internal static class OfficialIdentity {
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
        private static extern SafeFileHandle CreateFile(string path,uint access,uint sharing,IntPtr security,uint mode,uint flags,IntPtr template);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
        private static extern uint GetFinalPathNameByHandle(SafeFileHandle file,StringBuilder path,uint count,uint flags);
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] private struct FileInfo {
            internal uint Size; [MarshalAs(UnmanagedType.LPWStr)] internal string Path;
            internal IntPtr Handle; internal IntPtr KnownSubject;
        }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] private struct TrustData {
            internal uint Size; internal IntPtr PolicyData; internal IntPtr SipData;
            internal uint UiChoice; internal uint Revocation; internal uint UnionChoice;
            internal IntPtr FileInfo; internal uint StateAction; internal IntPtr State;
            internal IntPtr Reference; internal uint ProviderFlags; internal uint UiContext; internal IntPtr SignatureSettings;
        }
        [DllImport("wintrust.dll", ExactSpelling=true, CharSet=CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);
        internal static string CanonicalRoot(string root) {
            string result=System.IO.Path.GetFullPath(root).TrimEnd('\\');
            string pattern=@"^[A-Z]:\\(?:Program Files\\)?WindowsApps\\Claude_[0-9.]+_(x64|arm64)__pzs8sxrjxfjjc$";
            if(!Regex.IsMatch(result,pattern,RegexOptions.IgnoreCase|RegexOptions.CultureInvariant)) throw new InvalidOperationException("OFFICIAL_WINDOWSAPP_ROOT_REQUIRED");
            if(Directory.Exists(result)) {
                // Windows may relocate an Appx package to E:\WindowsApps and keep a managed junction on C:.
                // Resolve the root first, then pin the physical executable identity; nested links stay forbidden.
                using(SafeFileHandle handle=CreateFile(result,0,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero)) {
                    if(handle.IsInvalid)throw new InvalidOperationException("PACKAGE_ROOT_RESOLUTION_FAILED");
                    StringBuilder path=new StringBuilder(32768);uint length=GetFinalPathNameByHandle(handle,path,(uint)path.Capacity,0);
                    if(length==0||length>=path.Capacity)throw new InvalidOperationException("PACKAGE_ROOT_RESOLUTION_FAILED");
                    string physical=path.ToString(); if(physical.StartsWith(@"\\?\"))physical=physical.Substring(4);
                    if(!Regex.IsMatch(physical,pattern,RegexOptions.IgnoreCase|RegexOptions.CultureInvariant)||!System.IO.Path.GetFileName(physical).Equals(System.IO.Path.GetFileName(result),StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("PACKAGE_ROOT_TARGET_UNEXPECTED");
                    result=physical;
                }
            }
            return result;
        }
        internal static void CheckExecutablePath(string root,string executable) {
            string path=System.IO.Path.GetFullPath(executable);
            if(!path.StartsWith(root+"\\",StringComparison.OrdinalIgnoreCase) || !path.EndsWith(".exe",StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("TARGET_OUTSIDE_OFFICIAL_PACKAGE");
            string parent=path;
            while(parent.Length>=root.Length) {
                if(File.Exists(parent)||Directory.Exists(parent)) {
                    if((File.GetAttributes(parent)&FileAttributes.ReparsePoint)!=0) throw new InvalidOperationException("TARGET_REPARSE_POINT_DENIED");
                }
                parent=System.IO.Path.GetDirectoryName(parent);
                if(parent==null) break;
            }
        }
        internal static string HashFile(string path) {
            using(SHA256 sha=SHA256.Create()) using(FileStream stream=File.OpenRead(path)) return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","");
        }
        internal static void VerifyPublisher(string path) {
            FileInfo file=new FileInfo(); file.Size=(uint)Marshal.SizeOf(typeof(FileInfo)); file.Path=path;
            IntPtr ptr=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FileInfo)));
            try {
                Marshal.StructureToPtr(file,ptr,false);
                TrustData data=new TrustData(); data.Size=(uint)Marshal.SizeOf(typeof(TrustData));
                data.UiChoice=2; data.UnionChoice=1; data.FileInfo=ptr; data.ProviderFlags=0x1000;
                Guid action=new Guid("00aac56b-cd44-11d0-8cc2-00c04fc295ee");
                int result=WinVerifyTrust(new IntPtr(-1),ref action,ref data);
                if(result!=0) throw new InvalidOperationException("OFFICIAL_AUTHENTICODE_NOT_TRUSTED 0x"+result.ToString("X8"));
                using(X509Certificate2 cert=new X509Certificate2(X509Certificate.CreateFromSignedFile(path))) {
                    if(cert.Subject.IndexOf("Anthropic, PBC",StringComparison.Ordinal)<0) throw new InvalidOperationException("OFFICIAL_PUBLISHER_MISMATCH");
                }
            } finally { Marshal.DestroyStructure(ptr,typeof(FileInfo)); Marshal.FreeHGlobal(ptr); }
        }
        internal static List<ProgramRecord> Inventory(string suppliedRoot) {
            string root=CanonicalRoot(suppliedRoot);
            if(!Directory.Exists(root)) throw new DirectoryNotFoundException("OFFICIAL_PACKAGE_NOT_INSTALLED");
            List<ProgramRecord> result=new List<ProgramRecord>();
            foreach(string file in Directory.GetFiles(root,"*.exe",SearchOption.AllDirectories).OrderBy(p=>p,StringComparer.OrdinalIgnoreCase)) {
                CheckExecutablePath(root,file); VerifyPublisher(file);
                result.Add(new ProgramRecord { Path=System.IO.Path.GetFullPath(file), Sha256=HashFile(file) });
            }
            if(result.Count<1||result.Count>64||!result.Any(p=>p.Path.Equals(System.IO.Path.Combine(root,"app","Claude.exe"),StringComparison.OrdinalIgnoreCase))) throw new InvalidOperationException("OFFICIAL_INVENTORY_INCOMPLETE");
            return result;
        }
    }

    internal sealed class OfficialBoundary : IDisposable {
        private IntPtr engine;
        private readonly BoundaryJournal journal;
        private readonly Guid sublayer;
        private readonly List<Guid> keys=new List<Guid>();
        internal OfficialBoundary(BoundaryJournal source) {
            ValidateJournal(source); journal=source;
            sublayer=Key("sublayer",source.Root,source.ProxyPort);
            foreach(ProgramRecord program in source.Programs) for(int i=0;i<4;i++) keys.Add(Key("filter-"+i,program.Path,source.ProxyPort));
            Native.Session session=new Native.Session(); session.Key=Guid.NewGuid(); session.WaitMs=5000;
            session.Display.Name="HONG AI verified official executable boundary";
            Native.Check(Native.FwpmEngineOpen0(null,10,IntPtr.Zero,ref session,out engine),"open-official-boundary");
        }
        internal static Guid Key(string kind,string path,int port) {
            using(SHA256 sha=SHA256.Create()) {
                byte[] all=sha.ComputeHash(Encoding.UTF8.GetBytes("hongai.official-executable-boundary.v1|"+kind+"|"+path.ToLowerInvariant()+"|"+port));
                byte[] guid=new byte[16]; Array.Copy(all,guid,16); return new Guid(guid);
            }
        }
        internal static void ValidateJournal(BoundaryJournal data) {
            if(data==null||data.Schema!="hongai.official-executable-boundary.v1"||data.ProxyPort<1024||data.ProxyPort>65535||data.Programs==null||data.Programs.Count<1||data.Programs.Count>64) throw new InvalidOperationException("BOUNDARY_JOURNAL_INVALID");
            string root=OfficialIdentity.CanonicalRoot(data.Root);
            HashSet<string> seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(ProgramRecord program in data.Programs) {
                OfficialIdentity.CheckExecutablePath(root,program.Path);
                if(!seen.Add(program.Path)||!Regex.IsMatch(program.Sha256??"",@"^[A-F0-9]{64}$")) throw new InvalidOperationException("BOUNDARY_JOURNAL_PROGRAM_INVALID");
            }
            if(data.CustomerAccepted) throw new InvalidOperationException("DEVELOPMENT_BOUNDARY_CANNOT_ACCEPT_CUSTOMER");
        }
        private static Native.Condition Condition(Guid field,uint match,uint type,IntPtr pointer,uint value) {
            Native.Condition c=new Native.Condition(); c.Field=field; c.Match=match; c.Value.Type=type;
            if(type==12)c.Value.Data.Ptr=pointer; else if(type==1)c.Value.Data.U8=(byte)value;
            else if(type==2)c.Value.Data.U16=(ushort)value; else c.Value.Data.U32=value;
            return c;
        }
        private Native.Condition[] Conditions(IntPtr app,int kind) {
            Native.Condition first=Condition(Native.AppId,0,12,app,0);
            if(kind==0)return new[]{first,Condition(Native.RemoteAddress,10,3,IntPtr.Zero,0x7F000001)};
            if(kind==1)return new[]{first,Condition(Native.RemotePort,10,2,IntPtr.Zero,(uint)journal.ProxyPort)};
            if(kind==2)return new[]{first,Condition(Native.Protocol,10,1,IntPtr.Zero,6)};
            if(kind==3)return new[]{first};
            throw new InvalidOperationException("UNKNOWN_RULE_KIND");
        }
        internal void Install() {
            Native.Check(Native.FwpmTransactionBegin0(engine,0),"begin-install"); bool transaction=true;
            try {
                Native.Sublayer sub=new Native.Sublayer(); sub.Key=sublayer; sub.Flags=1; sub.Weight=0x7000; sub.Display.Name="HONGAI official executable boundary v1";
                Native.Check(Native.FwpmSubLayerAdd0(engine,ref sub,IntPtr.Zero),"add-sublayer");
                foreach(ProgramRecord program in journal.Programs) {
                    if(OfficialIdentity.HashFile(program.Path)!=program.Sha256) throw new InvalidOperationException("OFFICIAL_BINARY_CHANGED_DURING_INSTALL");
                    IntPtr app; Native.Check(Native.FwpmGetAppIdFromFileName0(program.Path,out app),"resolve-official-app-id");
                    try {
                        for(int kind=0;kind<4;kind++) {
                            Native.Condition[] conditions=Conditions(app,kind);
                            int size=Marshal.SizeOf(typeof(Native.Condition)); IntPtr memory=Marshal.AllocHGlobal(size*conditions.Length);
                            try {
                                for(int i=0;i<conditions.Length;i++)Marshal.StructureToPtr(conditions[i],IntPtr.Add(memory,i*size),false);
                                Native.Filter f=new Native.Filter(); f.Key=Key("filter-"+kind,program.Path,journal.ProxyPort); f.Flags=1;
                                f.Display.Name="HONGAI official executable boundary v1"; f.Layer=kind==3?Native.ConnectV6:Native.ConnectV4;
                                f.Sublayer=sublayer; f.Count=(uint)conditions.Length; f.Conditions=memory; f.Action.Type=0x1001; f.Weight.Type=1; f.Weight.Data.U8=15;
                                ulong id; Native.Check(Native.FwpmFilterAdd0(engine,ref f,IntPtr.Zero,out id),"add-official-app-rule");
                            } finally {Marshal.FreeHGlobal(memory);}
                        }
                    } finally {Native.FwpmFreeMemory0(ref app);}
                }
                Native.Check(Native.FwpmTransactionCommit0(engine),"commit-install"); transaction=false;
            } finally {if(transaction)Native.FwpmTransactionAbort0(engine);}
        }
        internal int Verify() {
            int count=0;
            foreach(ProgramRecord program in journal.Programs) {
                IntPtr app; Native.Check(Native.FwpmGetAppIdFromFileName0(program.Path,out app),"verify-app-id");
                try {
                    for(int kind=0;kind<4;kind++) {
                        Guid key=Key("filter-"+kind,program.Path,journal.ProxyPort); IntPtr pointer;
                        Native.Check(Native.FwpmFilterGetByKey0(engine,ref key,out pointer),"read-installed-rule");
                        try {
                            Native.Filter f=(Native.Filter)Marshal.PtrToStructure(pointer,typeof(Native.Filter));
                            Native.Condition[] expected=Conditions(app,kind);
                            if(f.Sublayer!=sublayer||f.Action.Type!=0x1001||f.Layer!=(kind==3?Native.ConnectV6:Native.ConnectV4)||f.Count!=expected.Length||(f.Flags&1)==0) throw new InvalidOperationException("INSTALLED_RULE_SHAPE_MISMATCH");
                            int size=Marshal.SizeOf(typeof(Native.Condition));
                            for(int i=0;i<expected.Length;i++) {
                                Native.Condition c=(Native.Condition)Marshal.PtrToStructure(IntPtr.Add(f.Conditions,i*size),typeof(Native.Condition));
                                if(c.Field!=expected[i].Field||c.Match!=expected[i].Match||c.Value.Type!=expected[i].Value.Type)throw new InvalidOperationException("INSTALLED_CONDITION_MISMATCH");
                                if(c.Value.Type==12) {
                                    Native.Blob observed=(Native.Blob)Marshal.PtrToStructure(c.Value.Data.Ptr,typeof(Native.Blob));
                                    Native.Blob wanted=(Native.Blob)Marshal.PtrToStructure(app,typeof(Native.Blob));
                                    if(observed.Size!=wanted.Size||observed.Size>65536)throw new InvalidOperationException("INSTALLED_APP_SCOPE_MISMATCH");
                                    byte[] a=new byte[(int)observed.Size],b=new byte[(int)wanted.Size];
                                    Marshal.Copy(observed.Data,a,0,a.Length);Marshal.Copy(wanted.Data,b,0,b.Length);
                                    if(!a.SequenceEqual(b))throw new InvalidOperationException("INSTALLED_APP_ID_MISMATCH");
                                } else {
                                    bool equal=c.Value.Type==1?c.Value.Data.U8==expected[i].Value.Data.U8:c.Value.Type==2?c.Value.Data.U16==expected[i].Value.Data.U16:c.Value.Data.U32==expected[i].Value.Data.U32;
                                    if(!equal)throw new InvalidOperationException("INSTALLED_ENDPOINT_MISMATCH");
                                }
                            }
                            count++;
                        } finally {Native.FwpmFreeMemory0(ref pointer);}
                    }
                } finally {Native.FwpmFreeMemory0(ref app);}
            }
            return count;
        }
        internal void Remove() {
            // Rule keys are derived from this product's namespace and validated official package paths.
            Native.Check(Native.FwpmTransactionBegin0(engine,0),"begin-rollback");bool transaction=true;
            try {
                foreach(Guid item in keys){Guid key=item;uint code=Native.FwpmFilterDeleteByKey0(engine,ref key);if(code!=0&&code!=0x80320003)Native.Check(code,"delete-owned-rule");}
                Guid sub=sublayer;uint subCode=Native.FwpmSubLayerDeleteByKey0(engine,ref sub);if(subCode!=0&&subCode!=0x80320007)Native.Check(subCode,"delete-owned-sublayer");
                Native.Check(Native.FwpmTransactionCommit0(engine),"commit-rollback");transaction=false;
            } finally {if(transaction)Native.FwpmTransactionAbort0(engine);}
        }
        public void Dispose(){if(engine!=IntPtr.Zero){Native.FwpmEngineClose0(engine);engine=IntPtr.Zero;}}
    }

    internal static class OfficialProgram {
        private static readonly JavaScriptSerializer Json=new JavaScriptSerializer {MaxJsonLength=262144};
        private static void RequireAdmin(){if(!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))throw new InvalidOperationException("ADMIN_REQUIRED");}
        private static string JournalPath(string supplied) {
            string path=System.IO.Path.GetFullPath(supplied);
            if(!Regex.IsMatch(path,@"^[DE]:\\",RegexOptions.IgnoreCase)||path.StartsWith(@"\\")||System.IO.Path.GetFileName(path)!="native-boundary.json")throw new InvalidOperationException("EXACT_D_OR_E_JOURNAL_REQUIRED");
            if(File.Exists(path)&&(File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new InvalidOperationException("JOURNAL_REPARSE_POINT");
            return path;
        }
        internal static int Main(string[] args) {
            try {
                if(args.Length==2&&args[0]=="--inventory") { Console.WriteLine(Json.Serialize(OfficialIdentity.Inventory(args[1])));return 0; }
                if(args.Length==4&&args[0]=="--install") {
                    RequireAdmin(); string root=OfficialIdentity.CanonicalRoot(args[1]); int port;
                    if(!Int32.TryParse(args[2],out port)||port<1024||port>65535)throw new InvalidOperationException("PROXY_PORT_INVALID");
                    string state=JournalPath(args[3]);if(File.Exists(state))throw new InvalidOperationException("JOURNAL_EXISTS_RECOVER_OR_REVIEW_FIRST");
                    BoundaryJournal journal=new BoundaryJournal {Root=root,ProxyPort=port,Phase="PREPARED",Programs=OfficialIdentity.Inventory(root)};
                    Directory.CreateDirectory(System.IO.Path.GetDirectoryName(state));
                    using(FileStream stream=new FileStream(state,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {
                        byte[] bytes=Encoding.UTF8.GetBytes(Json.Serialize(journal));stream.Write(bytes,0,bytes.Length);stream.Flush(true);
                    }
                    using(OfficialBoundary boundary=new OfficialBoundary(journal)){boundary.Install();Console.WriteLine("INSTALLED_VERIFIED_RULES="+boundary.Verify()+" customerAccepted=false");}
                    return 0;
                }
                if(args.Length==2&&(args[0]=="--verify"||args[0]=="--rollback")) {
                    RequireAdmin();string state=JournalPath(args[1]);
                    if(new System.IO.FileInfo(state).Length>262144)throw new InvalidOperationException("JOURNAL_TOO_LARGE");
                    BoundaryJournal journal=Json.Deserialize<BoundaryJournal>(File.ReadAllText(state,Encoding.UTF8));
                    using(OfficialBoundary boundary=new OfficialBoundary(journal)) {
                        if(args[0]=="--verify")Console.WriteLine("VERIFIED_RULES="+boundary.Verify()+" customerAccepted=false");
                        else {boundary.Remove();Console.WriteLine("EXACT_OFFICIAL_APP_RULES_REMOVED");}
                    }
                    if(args[0]=="--rollback")File.Move(state,state+".restored-"+Guid.NewGuid().ToString("N"));
                    return 0;
                }
                Console.WriteLine("Development only: --inventory root; --install root port D/E-state/native-boundary.json; --verify journal; --rollback journal");return 64;
            }catch(Exception ex){Console.Error.WriteLine(ex.Message);return 1;}
        }
    }
}
