using System;using System.Collections.Generic;using System.ComponentModel;using System.IO;using System.Runtime.InteropServices;
namespace HongAi.Brand {
    // Extract exact icon frames from a signed PE as data. No target code is run.
    public static class OfficialIcon {
        private delegate bool ResourceName(IntPtr module,IntPtr type,IntPtr name,IntPtr parameter);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern IntPtr LoadLibraryEx(string path,IntPtr file,uint flags);
        [DllImport("kernel32.dll")]private static extern bool FreeLibrary(IntPtr module);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern bool EnumResourceNames(IntPtr module,IntPtr type,ResourceName callback,IntPtr parameter);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern IntPtr FindResource(IntPtr module,IntPtr name,IntPtr type);
        [DllImport("kernel32.dll",SetLastError=true)]private static extern uint SizeofResource(IntPtr module,IntPtr resource);
        [DllImport("kernel32.dll",SetLastError=true)]private static extern IntPtr LoadResource(IntPtr module,IntPtr resource);
        [DllImport("kernel32.dll")]private static extern IntPtr LockResource(IntPtr resource);
        private static byte[] Bytes(IntPtr module,IntPtr name,int type){IntPtr r=FindResource(module,name,new IntPtr(type));if(r==IntPtr.Zero)throw new Win32Exception();uint size=SizeofResource(module,r);if(size==0||size>8*1024*1024)throw new InvalidDataException("ICON_RESOURCE_SIZE");IntPtr data=LockResource(LoadResource(module,r));if(data==IntPtr.Zero)throw new Win32Exception();byte[] bytes=new byte[(int)size];Marshal.Copy(data,bytes,0,bytes.Length);return bytes;}
        public static void Export(string executable,string destination){
            IntPtr module=LoadLibraryEx(executable,IntPtr.Zero,0x22);if(module==IntPtr.Zero)throw new Win32Exception();
            try{
                byte[] group=null;ResourceName callback=delegate(IntPtr m,IntPtr t,IntPtr n,IntPtr p){group=Bytes(m,n,14);return false;};EnumResourceNames(module,new IntPtr(14),callback,IntPtr.Zero);GC.KeepAlive(callback);
                if(group==null||group.Length<6||BitConverter.ToUInt16(group,2)!=1)throw new InvalidDataException("OFFICIAL_APP_ICON_MISSING");
                int count=BitConverter.ToUInt16(group,4);if(count<1||count>64||group.Length<6+count*14)throw new InvalidDataException("ICON_GROUP_INVALID");
                var frames=new List<byte[]>();for(int i=0;i<count;i++)frames.Add(Bytes(module,new IntPtr(BitConverter.ToUInt16(group,6+i*14+12)),3));
                using(var stream=new FileStream(destination,FileMode.CreateNew,FileAccess.Write))using(var writer=new BinaryWriter(stream)){
                    writer.Write((ushort)0);writer.Write((ushort)1);writer.Write((ushort)count);int offset=6+count*16;
                    for(int i=0;i<count;i++){writer.Write(group,6+i*14,8);writer.Write(frames[i].Length);writer.Write(offset);offset+=frames[i].Length;}
                    foreach(byte[] frame in frames)writer.Write(frame);
                }
            }finally{FreeLibrary(module);}
        }
    }
}
