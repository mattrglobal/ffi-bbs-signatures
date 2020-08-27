using System;
using System.Runtime.InteropServices;

namespace Hyperledger.Ursa.BbsSignatures
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ByteBuffer
    {
        public ulong Length;
        public IntPtr Data;
    }
}