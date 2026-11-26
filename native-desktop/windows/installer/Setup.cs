using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

internal static class Setup {
    private static void ExtractPayload(string work) {
        Directory.CreateDirectory(work);
        string archive=Path.Combine(work,"payload.zip");
        using(Stream source=Assembly.GetExecutingAssembly().GetManifestResourceStream("hongai.payload"))
        using(FileStream target=File.Create(archive)){if(source==null)throw new Exception("Missing installer payload");source.CopyTo(target);}
        string expected;
        using(Stream source=Assembly.GetExecutingAssembly().GetManifestResourceStream("hongai.payload.sha256"))
        using(StreamReader reader=new StreamReader(source)){expected=reader.ReadToEnd().Trim();}
        using(SHA256 sha=SHA256.Create())using(FileStream stream=File.OpenRead(archive)){
            if(BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","")!=expected)throw new Exception("Installer payload hash mismatch");
        }
        ZipFile.ExtractToDirectory(archive,work);
    }
    [STAThread] private static int Main(string[] args) {
        if(args.Length==2&&args[0]=="--verify-payload"){
            string test=Path.GetFullPath(args[1]);
            if(!(test.StartsWith(@"D:\",StringComparison.OrdinalIgnoreCase)||test.StartsWith(@"E:\",StringComparison.OrdinalIgnoreCase))||Directory.Exists(test))return 64;
            try {ExtractPayload(test);File.WriteAllText(Path.Combine(test,"payload-verification.json"),"{\"verified\":true,\"installed\":false}");return 0;}
            catch{return 1;}
        }
        Application.EnableVisualStyles();
        string drive=Directory.Exists(@"E:\")?"E:":Directory.Exists(@"D:\")?"D:":null;
        if(drive==null){MessageBox.Show("需要可用的 D 盘或 E 盘。","HONG AI CAGE");return 1;}
        string work=Path.Combine(drive+@"\HONGAI-CAGE-InstallWork",Guid.NewGuid().ToString("N"));
        try {
            if(MessageBox.Show("安装 HONG AI CAGE 桌面守卫测试版？\n\n默认安装到数据盘，不更改 Clash、Wi-Fi、系统 DNS 或路由。\n需已安装官方 Claude Desktop。当前 MCP、Cowork、扩展暂受限，尚未完成客户正式验收。","HONG AI CAGE",MessageBoxButtons.OKCancel,MessageBoxIcon.Information)!=DialogResult.OK)return 0;
            ExtractPayload(work);
            string script=Path.Combine(work,"Install-DesktopGuard.ps1");
            ProcessStartInfo start=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),@"System32\WindowsPowerShell\v1.0\powershell.exe"));
            start.Arguments="-NoLogo -NoProfile -ExecutionPolicy Bypass -File \""+script+"\"";
            start.UseShellExecute=false;start.CreateNoWindow=true;start.RedirectStandardOutput=true;start.RedirectStandardError=true;
            start.EnvironmentVariables["TEMP"]=work;start.EnvironmentVariables["TMP"]=work;
            using(Process process=Process.Start(start)){
                var outputTask=process.StandardOutput.ReadToEndAsync();var errorTask=process.StandardError.ReadToEndAsync();process.WaitForExit();
                string output=outputTask.GetAwaiter().GetResult();string error=errorTask.GetAwaiter().GetResult();
                File.WriteAllText(Path.Combine(work,"install-output.txt"),output+Environment.NewLine+error,Encoding.UTF8);
                if(process.ExitCode!=0)throw new Exception("安装未完成：\n"+error+"\n日志："+work);
            }
            MessageBox.Show("安装完成。桌面已生成“HONG AI CAGE 桌面守卫（测试）”。\n\n首次启动时选择第一阶段生成的 Clash 交接文件。启动及回滚会请求应用专用管理员授权。\n本次未启动或登录 Claude。","HONG AI CAGE",MessageBoxButtons.OK,MessageBoxIcon.Information);
            return 0;
        } catch(Exception error){MessageBox.Show(error.Message,"HONG AI CAGE 安装停止",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}
    }
}
