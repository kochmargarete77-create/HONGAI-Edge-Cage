using System;using System.Diagnostics;using System.IO;using System.Runtime.InteropServices;using System.Text;
internal static class SessionControl {
    [DllImport("SbieDll.dll",CharSet=CharSet.Unicode)] static extern int SbieApi_QueryProcess(IntPtr pid,StringBuilder box,StringBuilder image,StringBuilder sid,out uint session);
    public static int Main(string[] args){
        if(args.Length!=3)return 64;string boxName=args[0],report=args[2];int port;
        if(!boxName.StartsWith("HONGAI_CAGE_",StringComparison.Ordinal)||!Int32.TryParse(args[1],out port)||port<1024||port>65535)return 64;
        try{
            var box=new StringBuilder(34);var image=new StringBuilder(96);var sid=new StringBuilder(96);uint session;
            if(SbieApi_QueryProcess(new IntPtr(Process.GetCurrentProcess().Id),box,image,sid,out session)!=0||box.ToString()!=boxName)return 90;
            using(var key=Microsoft.Win32.Registry.CurrentUser.CreateSubKey("SOFTWARE\\Policies\\Claude")){
                key.SetValue("egressProxyUrl","http://127.0.0.1:"+port,Microsoft.Win32.RegistryValueKind.String);
                key.SetValue("secureVmFeaturesEnabled",0,Microsoft.Win32.RegistryValueKind.DWord);
                key.SetValue("isLocalDevMcpEnabled",1,Microsoft.Win32.RegistryValueKind.DWord);
                key.SetValue("isDesktopExtensionEnabled",1,Microsoft.Win32.RegistryValueKind.DWord);
                key.SetValue("isDesktopExtensionDirectoryEnabled",1,Microsoft.Win32.RegistryValueKind.DWord);
                key.SetValue("isClaudeCodeForDesktopEnabled",0,Microsoft.Win32.RegistryValueKind.DWord);
                key.SetValue("disableAutoUpdates",1,Microsoft.Win32.RegistryValueKind.DWord);
            }
            File.WriteAllText(report,"POLICY_READY|"+boxName+"|"+port,Encoding.UTF8);return 0;
        }catch{return 1;}
    }
}
