using System;using System.Diagnostics;using System.IO;using System.Windows.Forms;
internal static class CageLauncher {
    [STAThread] public static int Main(string[] args){
        string root=AppDomain.CurrentDomain.BaseDirectory;
        string script=Path.Combine(root,"Cage-UI.ps1");
        if(!File.Exists(script)||!File.Exists(Path.Combine(root,"installation.json"))){MessageBox.Show("安装不完整，请重新安装 HONG AI CAGE。","HONG AI CAGE");return 1;}
        var start=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),@"System32\WindowsPowerShell\v1.0\powershell.exe"));
        start.Arguments="-NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File \""+script+"\"";
        if(args.Length==1&&args[0]=="--ui-smoke-test")start.Arguments+=" -UISmokeTest";
        start.UseShellExecute=false;start.CreateNoWindow=true;start.WorkingDirectory=root;
        using(Process process=Process.Start(start)){process.WaitForExit();return process.ExitCode;}
    }
}
