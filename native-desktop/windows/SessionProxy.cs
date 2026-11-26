using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace HongAi {
    public static class ProxyDestinationPolicy {
        public static bool Permitted(string firstLine){
            if(String.IsNullOrEmpty(firstLine)||firstLine.Length>4096)return false;
            string[] parts=firstLine.Split(' ');
            if(parts.Length!=3||parts[0]!="CONNECT"||(parts[2]!="HTTP/1.1"&&parts[2]!="HTTP/1.0"))return false;
            Uri target;if(!Uri.TryCreate("https://"+parts[1],UriKind.Absolute,out target)||target.UserInfo!=""||target.AbsolutePath!="/"||target.Query!=""||target.Fragment!=""||target.Port<1||target.Port>65535)return false;
            string host=target.DnsSafeHost.Trim('[',']').TrimEnd('.').ToLowerInvariant();
            IPAddress ip;if(IPAddress.TryParse(host,out ip)){
                if(ip.IsIPv4MappedToIPv6)ip=ip.MapToIPv4();
                byte[] b=ip.GetAddressBytes();
                if(b.Length==16)return !IPAddress.IsLoopback(ip)&&!ip.IsIPv6LinkLocal&&!ip.IsIPv6SiteLocal&&!ip.IsIPv6Multicast&&(b[0]&0xE0)==0x20;
                return b[0]>0&&b[0]<224&&b[0]!=10&&b[0]!=127&&!(b[0]==169&&b[1]==254)&&!(b[0]==172&&b[1]>=16&&b[1]<=31)&&!(b[0]==192&&b[1]==168)&&!(b[0]==100&&b[1]>=64&&b[1]<=127)&&!(b[0]==198&&(b[1]==18||b[1]==19));
            }
            if(!host.Contains(".")||host.Length>253)return false;
            foreach(string suffix in new[]{".localhost",".local",".internal",".lan",".home",".arpa"})if(host.EndsWith(suffix,StringComparison.Ordinal))return false;
            foreach(char c in host)if(!(c>='a'&&c<='z'||c>='0'&&c<='9'||c=='-'||c=='.'))return false;
            return true;
        }
    }
    // No DNS, no remote-host selection, no DIRECT path. This endpoint forwards
    // only to the one numeric loopback proxy provided by the first stage.
    public sealed class SessionProxy : IDisposable {
        private readonly TcpListener listener=new TcpListener(IPAddress.Loopback,0);
        private readonly HashSet<TcpClient> clients=new HashSet<TcpClient>();
        private readonly object gate=new object();
        private readonly int upstream;
        private readonly Timer expiry;
        private long validUntil;
        private bool stopped;
        public int Port {get;private set;}
        public SessionProxy(int upstreamPort,int leaseMilliseconds) {
            if(upstreamPort<1024||upstreamPort>65535)throw new ArgumentOutOfRangeException("upstreamPort");
            upstream=upstreamPort;Refresh(leaseMilliseconds);listener.Start(32);Port=((IPEndPoint)listener.LocalEndpoint).Port;
            expiry=new Timer(delegate{if(Stopwatch.GetTimestamp()>=Interlocked.Read(ref validUntil))Dispose();},null,250,250);
            Task.Run((Func<Task>)Accept);
        }
        public void Refresh(int milliseconds){if(milliseconds<500||milliseconds>30000)throw new ArgumentOutOfRangeException("milliseconds");lock(gate){if(stopped)throw new ObjectDisposedException("session proxy");Interlocked.Exchange(ref validUntil,Stopwatch.GetTimestamp()+(long)milliseconds*Stopwatch.Frequency/1000);}}
        private async Task Accept(){
            while(true){
                TcpClient incoming;
                try{incoming=await listener.AcceptTcpClientAsync().ConfigureAwait(false);}catch{return;}
                lock(gate){if(stopped||clients.Count>=64||Stopwatch.GetTimestamp()>=Interlocked.Read(ref validUntil)){incoming.Close();continue;}clients.Add(incoming);}
                Task.Run(()=>Forward(incoming));
            }
        }
        private async Task Forward(TcpClient incoming){
            TcpClient outgoing=new TcpClient(AddressFamily.InterNetwork);
            try{
                lock(gate){if(stopped)return;clients.Add(outgoing);}
                Task<byte[]> headerTask=ReadHeader(incoming.GetStream());
                if(await Task.WhenAny(headerTask,Task.Delay(5000)).ConfigureAwait(false)!=headerTask)return;
                byte[] header=await headerTask.ConfigureAwait(false);
                if(header==null)return;
                string firstLine=Encoding.ASCII.GetString(header).Split(new[]{"\r\n"},StringSplitOptions.None)[0];
                if(!ProxyDestinationPolicy.Permitted(firstLine))return;
                Task connect=outgoing.ConnectAsync(IPAddress.Loopback,upstream);
                if(await Task.WhenAny(connect,Task.Delay(2000)).ConfigureAwait(false)!=connect)return;
                await connect.ConfigureAwait(false);
                NetworkStream left=incoming.GetStream(),right=outgoing.GetStream();
                await right.WriteAsync(header,0,header.Length).ConfigureAwait(false);
                await Task.WhenAny(Pump(left,right),Pump(right,left)).ConfigureAwait(false);
            }catch{}finally{incoming.Close();outgoing.Close();lock(gate){clients.Remove(incoming);clients.Remove(outgoing);}}
        }
        private static async Task<byte[]> ReadHeader(NetworkStream source){
            try{using(MemoryStream result=new MemoryStream()){
                byte[] buffer=new byte[1024];
                while(result.Length<16384){int count=await source.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false);if(count==0)return null;result.Write(buffer,0,count);byte[] bytes=result.ToArray();for(int i=3;i<bytes.Length;i++)if(bytes[i-3]==13&&bytes[i-2]==10&&bytes[i-1]==13&&bytes[i]==10)return bytes;}
                return null;
            }}catch(IOException){return null;}catch(ObjectDisposedException){return null;}
        }
        private static async Task Pump(NetworkStream source,NetworkStream destination){
            byte[] buffer=new byte[65536];int count;
            try{while((count=await source.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false))>0)await destination.WriteAsync(buffer,0,count).ConfigureAwait(false);}catch(IOException){}catch(ObjectDisposedException){}
        }
        public void Dispose(){lock(gate){if(stopped)return;stopped=true;Interlocked.Exchange(ref validUntil,0);listener.Stop();foreach(TcpClient client in clients)client.Close();clients.Clear();if(expiry!=null)expiry.Dispose();}}
    }
}
