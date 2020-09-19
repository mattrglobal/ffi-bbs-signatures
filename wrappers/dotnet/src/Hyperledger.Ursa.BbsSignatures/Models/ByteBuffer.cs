using System;
using System.Runtime.InteropServices;

namespace Hyperledger.Ursa.BbsSignatures
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ByteBuffer
    {
        public ulong Length;
        public IntPtr Data;

        public static ByteBuffer None = new ByteBuffer { Length = 0, Data = IntPtr.Zero };
    }
}