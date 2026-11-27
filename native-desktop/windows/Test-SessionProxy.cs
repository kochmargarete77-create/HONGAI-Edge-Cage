using System;using System.Net;using System.Net.Sockets;using System.Threading;using System.Threading.Tasks;using System.Text;
internal static class SessionProxyProof {
    private static int checks;
    private static void Assert(bool condition,string label){if(!condition)throw new Exception(label);checks++;Console.WriteLine("PASS "+label);}
    private const string Request="CONNECT fixture.example:443 HTTP/1.1\r\nHost: fixture.example:443\r\n\r\n";
    private static bool Exchange(int port){try{using(TcpClient c=new TcpClient()){c.ReceiveTimeout=1500;c.SendTimeout=1500;c.Connect(IPAddress.Loopback,port);byte[] data=Encoding.UTF8.GetBytes(Request);var stream=c.GetStream();stream.Write(data,0,data.Length);byte[] read=new byte[data.Length];int total=0;while(total<read.Length){int n=stream.Read(read,total,read.Length-total);if(n==0)break;total+=n;}return total==data.Length&&Encoding.UTF8.GetString(read)==Request;}}catch{return false;}}
    public static int Main(){
        TcpListener upstream=new TcpListener(IPAddress.Loopback,0);upstream.Start();
        Task.Run(async delegate {try{while(true){TcpClient c=await upstream.AcceptTcpClientAsync();Task.Run(async delegate{using(c){try{byte[] data=new byte[65536];int n;while((n=await c.GetStream().ReadAsync(data,0,data.Length))>0)await c.GetStream().WriteAsync(data,0,n);}catch{}}});}}catch{}});
        try{
            int target=((IPEndPoint)upstream.LocalEndpoint).Port;
            using(var proxy=new HongAi.SessionProxy(target,1000)){
                for(int i=0;i<4;i++){Assert(Exchange(proxy.Port),"session relay roundtrip "+i);proxy.Refresh(1000);}
                Thread.Sleep(1400);Assert(!Exchange(proxy.Port),"expired lease closes session endpoint");
                proxy.Refresh(1000);Assert(!Exchange(proxy.Port),"heartbeat cannot reopen a paused gateway");
                proxy.Resume(1000);Assert(Exchange(proxy.Port),"explicit verified resume retains the same endpoint");
            }
            using(var proxy=new HongAi.SessionProxy(target,5000)){
                int port=proxy.Port;Assert(Exchange(port),"fresh session relay works");proxy.Suspend();Assert(!Exchange(port),"suspended gateway rejects traffic");proxy.Resume(5000);Assert(Exchange(port),"resume preserves the protected port");proxy.Dispose();Assert(!Exchange(port),"supervisor stop closes session endpoint");
            }
            using(var proxy=new HongAi.SessionProxy(target,750))using(var active=new TcpClient()){
                active.ReceiveTimeout=2000;active.Connect(IPAddress.Loopback,proxy.Port);byte[] bytes=Encoding.ASCII.GetBytes(Request);var stream=active.GetStream();stream.Write(bytes,0,bytes.Length);byte[] output=new byte[bytes.Length];int received=0;while(received<output.Length){int n=stream.Read(output,received,output.Length-received);if(n==0)break;received+=n;}Assert(received==bytes.Length&&Encoding.ASCII.GetString(output)==Request,"active tunnel carries traffic before lease expiry");
                Thread.Sleep(1100);bool closed=false;try{closed=stream.Read(output,0,output.Length)==0;}catch{closed=true;}Assert(closed,"lease expiry closes already-established tunnel");
            }
            foreach(string destination in new[]{"127.0.0.1:9090","[::1]:9090","169.254.169.254:80","2130706433:80","10.0.0.1:80","metadata.google.internal:80","user@fixture.example:443"})Assert(!HongAi.ProxyDestinationPolicy.Permitted("CONNECT "+destination+" HTTP/1.1"),"local/metadata destination rejected "+destination);
            Console.WriteLine("SESSION_PROXY_PROOF_PASS checks="+checks);return 0;
        }finally{upstream.Stop();}
    }
}
