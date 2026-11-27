using System;using System.Diagnostics;using System.IO;using System.Threading;using System.Windows.Forms;
internal static class CageLauncher {
    [STAThread] public static int Main(string[] args){
        bool created;using(var instance=new Mutex(true,"Local\\HONGAI_CAGE_UI_"+System.Security.Principal.WindowsIdentity.GetCurrent().User.Value,out created)){
        if(!created){MessageBox.Show("HONG AI CAGE 已运行。设置与停止操作请使用任务栏右下角的 CAGE 图标。","HONG AI CAGE");return 0;}
        string root=AppDomain.CurrentDomain.BaseDirectory;
        string script=Path.Combine(root,"Cage-UI.ps1");
        if(!File.Exists(script)||!File.Exists(Path.Combine(root,"installation.json"))){MessageBox.Show("安装不完整，请重新安装 HONG AI CAGE。","HONG AI CAGE");return 1;}
        var start=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),@"System32\WindowsPowerShell\v1.0\powershell.exe"));
        start.Arguments="-NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File \""+script+"\"";
        if(args.Length==1&&args[0]=="--ui-smoke-test")start.Arguments+=" -UISmokeTest";
        if(args.Length==1&&args[0]=="--settings")start.Arguments+=" -Settings";
        if(args.Length==1&&args[0]=="--daily-launch-smoke-test")start.Arguments+=" -DailyLaunchSmokeTest";
        start.UseShellExecute=false;start.CreateNoWindow=true;start.WorkingDirectory=root;
        using(Process process=Process.Start(start)){process.WaitForExit();return process.ExitCode;}
        }
    }
}
