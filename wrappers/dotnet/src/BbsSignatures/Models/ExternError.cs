using System;
using System.Runtime.InteropServices;

namespace BbsSignatures
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ExternError
    {
        internal int Code;
        internal IntPtr Message;
    }
}