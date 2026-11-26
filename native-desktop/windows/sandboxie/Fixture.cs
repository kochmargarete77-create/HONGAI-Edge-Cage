using System;using System.Diagnostics;using System.IO;using System.Net;using System.Net.Sockets;using System.Runtime.InteropServices;using System.Text;
internal static class Fixture {
    [DllImport("SbieDll.dll",CharSet=CharSet.Unicode)] private static extern int SbieApi_QueryProcess(IntPtr pid,StringBuilder box,StringBuilder image,StringBuilder sid,out uint session);
    private static int Connect(string address,int port){try{IPAddress ip=IPAddress.Parse(address);using(TcpClient client=new TcpClient(ip.AddressFamily)){var task=client.ConnectAsync(ip,port);return task.Wait(1500)&&client.Connected?0:13;}}catch{return 13;}}
    public static int Main(string[] args){
        if(args.Length<5)return 64;
        string mode=args[0],boxName=args[1],report=args[2],root=args[3];int port=Int32.Parse(args[4]);
        try{
            var box=new StringBuilder(34);var image=new StringBuilder(96);var sid=new StringBuilder(96);uint session;
            if(SbieApi_QueryProcess(new IntPtr(Process.GetCurrentProcess().Id),box,image,sid,out session)!=0||box.ToString()!=boxName)return 90;
            int result=0;
            if(mode=="identity")result=0;
            else if(mode=="connect")result=Connect("127.0.0.1",port);
            else if(mode=="ipv6")result=Connect("::1",port);
            else if(mode=="read-secret"){try{File.ReadAllText(Path.Combine(root,"private","secret.txt"));result=0;}catch{result=13;}}
            else if(mode=="workspace"){File.WriteAllText(Path.Combine(root,"workspace","approved-result.txt"),"owned fixture");result=0;}
            else if(mode=="nested"){
                string secondary=Path.Combine(Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName),"secondary-fixture.exe");
                string childReport=report+".child";
                var start=new ProcessStartInfo(secondary,"connect "+boxName+" \""+childReport+"\" \""+root+"\" "+port);start.UseShellExecute=false;start.CreateNoWindow=true;
                using(Process child=Process.Start(start)){if(!child.WaitForExit(5000)){child.Kill();result=124;}else{string text=File.ReadAllText(childReport);result=Int32.Parse(text.Split('|')[0]);}}
            }else return 64;
            File.WriteAllText(report,result+"|"+box.ToString());return result;
        }catch(Exception error){try{File.WriteAllText(report,"ERROR|"+error.GetType().Name+"|"+error.Message);}catch{}return 1;}
    }
}
