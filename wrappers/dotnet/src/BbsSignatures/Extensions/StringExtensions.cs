using System;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace BbsSignatures
{
    public static class StringExtensions
    {
        /// <summary>
        /// Ases the bytes.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <returns></returns>
        public static byte[] AsBytes(this string message) => Encoding.UTF8.GetBytes(message);

        /// <summary>
        /// Convert a Base64 string into byte array
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public static byte[] AsBytesFromBase64(this string message) => Convert.FromBase64String(message);

        /// <summary>
        /// Decodes the base64 encoded string
        /// </summary>
        /// <param name="message">The message.</param>
        /// <returns></returns>
        public static byte[] DecodeBase64(this string message) => Convert.FromBase64String(message);
    }
}