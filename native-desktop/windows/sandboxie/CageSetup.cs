using System;using System.Diagnostics;using System.IO;using System.IO.Compression;using System.Reflection;using System.Security.Cryptography;using System.Security.Principal;using System.Text;using System.Windows.Forms;
internal static class CageSetup {
    static void Extract(string directory){
        Directory.CreateDirectory(directory);string zip=Path.Combine(directory,"payload.zip"),expected;
        using(var s=Assembly.GetExecutingAssembly().GetManifestResourceStream("cage.payload"))using(var f=File.Create(zip))s.CopyTo(f);
        using(var s=Assembly.GetExecutingAssembly().GetManifestResourceStream("cage.hash"))using(var r=new StreamReader(s))expected=r.ReadToEnd().Trim();
        using(var sha=SHA256.Create())using(var f=File.OpenRead(zip))if(BitConverter.ToString(sha.ComputeHash(f)).Replace("-","")!=expected)throw new Exception("安装包校验未通过。");
        ZipFile.ExtractToDirectory(zip,directory);
    }
    [STAThread] static int Main(string[] args){
        bool verify=args.Length==2&&args[0]=="--verify-payload";
        bool ci=args.Length==2&&args[0]=="--install-for-ci"&&Environment.GetEnvironmentVariable("GITHUB_ACTIONS")=="true";
        if(verify){string path=Path.GetFullPath(args[1]);if(Directory.Exists(path)||!path.StartsWith(@"D:\",StringComparison.OrdinalIgnoreCase)&&!path.StartsWith(@"E:\",StringComparison.OrdinalIgnoreCase))return 64;try{Extract(path);return 0;}catch{return 1;}}
        Application.EnableVisualStyles();
        string drive=null;
        if(ci)drive=Path.GetPathRoot(Path.GetFullPath(args[1])).TrimEnd('\\');
        else foreach(string candidate in new[]{Path.GetPathRoot(Assembly.GetExecutingAssembly().Location),@"E:\",@"D:\"}){
            if(String.IsNullOrEmpty(candidate)||!(candidate.StartsWith("D:",StringComparison.OrdinalIgnoreCase)||candidate.StartsWith("E:",StringComparison.OrdinalIgnoreCase)))continue;
            try{var info=new DriveInfo(candidate);if(info.IsReady&&info.DriveType==DriveType.Fixed&&info.AvailableFreeSpace>512L*1024*1024){drive=candidate.TrimEnd('\\');break;}}catch{}
        }
        string work=drive!=null?Path.Combine(drive+@"\HONGAI-CAGE-InstallWork",Guid.NewGuid().ToString("N")):Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"HONGAI-CAGE-InstallWork",Guid.NewGuid().ToString("N"));
        try{
            if(!ci&&MessageBox.Show("安装 HONG AI CAGE 桌面隔离测试版？\n\n包含未修改的 Sandboxie Classic 签名隔离组件（GPLv3）。复用已安装的官方 Claude Desktop。\n工程与登录数据优先放数据盘，不修改 Wi-Fi、Clash、TUN、系统 DNS 或路由，不重启。\n本地 MCP、文件与桌面扩展在专用环境运行；Cowork 虚拟机与系统级集成暂不启用。\n账号登录及真实业务仍需在操作者在场时验收。", "HONG AI CAGE",MessageBoxButtons.OKCancel,MessageBoxIcon.Information)!=DialogResult.OK)return 0;
            Extract(work);string result=Path.Combine(work,"installation-result.json");
            var start=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),@"System32\WindowsPowerShell\v1.0\powershell.exe"));
            string owner=WindowsIdentity.GetCurrent().User.Value,desktop=Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            start.Arguments="-NoLogo -NoProfile -ExecutionPolicy Bypass -File \""+Path.Combine(work,"Install-Cage.ps1")+"\" -ResultPath \""+result+"\" -OriginalUserSid "+owner+" -OriginalDesktop \""+desktop+"\"";
            if(ci)start.Arguments+=" -Destination \""+Path.GetFullPath(args[1])+"\" -NoShortcut";
            bool admin=new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            start.UseShellExecute=!admin;start.CreateNoWindow=admin;start.WindowStyle=ProcessWindowStyle.Hidden;
            if(!admin)start.Verb="runas";
            using(var p=Process.Start(start)){p.WaitForExit();if(ci){string destination=Environment.GetEnvironmentVariable("HONGAI_CAGE_CI_RESULT");if(!String.IsNullOrEmpty(destination)&&File.Exists(result))File.Copy(result,destination,true);}if(p.ExitCode!=0||!File.Exists(result))throw new Exception("安装未完成，请查看："+work);}
            if(!ci)MessageBox.Show("安装完成。请从桌面的 HONG AI CAGE 打开。\n首次导入第一步交接文件，并选择工作文件夹。\n以后启动会自动重新核对已保存的最终出口。\n本次未登录 Claude。","HONG AI CAGE");
            return 0;
        }catch(Exception error){if(!ci)MessageBox.Show(error.Message,"HONG AI CAGE 安装停止");else{string destination=Environment.GetEnvironmentVariable("HONGAI_CAGE_CI_RESULT");if(!String.IsNullOrEmpty(destination)&&!File.Exists(destination))File.WriteAllText(destination,error.ToString());}return 1;}
    }
}
