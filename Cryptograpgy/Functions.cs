using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpHash.Base;
using System.Security.Cryptography;
using Org.BouncyCastle.Utilities.Encoders;
using static System.Net.Mime.MediaTypeNames;
using static SharpHash.Base.HashFactory;

namespace Cryptograpgy
{
    internal class Functions
    {
        static Random randomgenerator = new Random();
        public const string CBC = "CBC";
        public const string ECB = "ECB";
        public const string OFB = "OBF";
        public const string CFB = "CFB";

        public static string rand()
        {
            string ch = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            int LOM = randomgenerator.Next(5, 8);
            return new string(Enumerable.Repeat(ch, LOM).Select(s => s[randomgenerator.Next(s.Length)]).ToArray());
        }
        public static byte[] arraydump(params object[] Arrs)
        {
            int len = 0;
            foreach (object byo in Arrs)
            {
                if (byo.GetType() == typeof(byte[]))
                    len += byo.ToByteArray().Length;
                else if (byo.GetType() == typeof(byte) || byo.GetType() == typeof(int))
                    len += 1;
                else
                    len += Encoding.UTF8.GetBytes(byo.ToString()).Length;
            }
            byte[] RtnArr = new byte[len];
            int index = 0;
            foreach (object Arr in Arrs)
            {
                if (Arr.GetType() == typeof(byte[]))
                {
                    Arr.ToByteArray().CopyTo(RtnArr, index);
                    index += Arr.ToByteArray().Length;
                }
                else if (Arr.GetType() == typeof(byte) || Arr.GetType() == typeof(int))
                {
                    RtnArr[index] = Convert.ToByte(Arr);
                    index += 1;
                }
                else
                {
                    byte[] by = getbytes(Arr.ToString());
                    by.CopyTo(RtnArr, index);
                    index += by.Length;
                }
            }
            return RtnArr;
        }

        public static dynamic getbytes(string str)
        {
            return Encoding.UTF8.GetBytes(str);
        }

        //GZip

        public static byte[] Compress(byte[] text)
        {
            using MemoryStream memoryStream1 = new MemoryStream(text);
            using MemoryStream memoryStream2 = new MemoryStream();
            using (GZipStream gzipStream = new GZipStream(memoryStream2, CompressionMode.Compress))
                memoryStream1.CopyTo(gzipStream);
            return memoryStream2.ToArray();
        }

        public static byte[] Decompress(byte[] tounzip)
        {
            using MemoryStream memoryStream1 = new MemoryStream(tounzip);
            using MemoryStream memoryStream2 = new MemoryStream();
            using (GZipStream gzipStream = new GZipStream(memoryStream1, CompressionMode.Decompress))
                gzipStream.CopyTo(memoryStream2);
            return memoryStream2.ToArray();
        }


        //HASH

        public static byte[] md5(byte[] input)
        {
            return HashFactory.Crypto.CreateMD5().ComputeBytes(input).GetBytes();
        }

        public static byte[] sha1(byte[] input)
        {
            return HashFactory.Crypto.CreateSHA1().ComputeBytes(input).GetBytes();
        }
        public static byte[] sha256(byte[] input)
        {
            return HashFactory.Crypto.CreateSHA2_256().ComputeBytes(input).GetBytes();
        }

        //ENC

        public static CipherMode AesMode(string mode)
        {
            mode = mode.ToLower().Trim();
            if (mode == "cts") return CipherMode.CTS;
            else if (mode == "ecb") return CipherMode.ECB;
            else if (mode == "ofb") return CipherMode.OFB;
            else if (mode == "cfb") return CipherMode.CFB;
            else return CipherMode.CBC;
        }
        public static CipherMode AesMode(int mode)
        {
            if (mode == 0) return CipherMode.CBC;
            else if (mode == 1) return CipherMode.ECB;
            else if (mode == 2) return CipherMode.OFB;
            else if (mode == 3) return CipherMode.CFB;
            else return CipherMode.CBC;
        }

        public static byte[] aesencrypt(byte[] str, byte[] key, byte[] iv = null, string mode = CBC)
        {
            byte[] bytes = str;
            byte[] inArray = null;
            using (Aes aes = new AesManaged())
            {
                aes.Key = key;

                if( iv != null )
                    aes.IV = iv;

                aes.Mode = AesMode(mode);
                aes.Padding = PaddingMode.PKCS7;
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(bytes, 0, bytes.Length);
                        cryptoStream.Close();
                    }
                    inArray = memoryStream.ToArray();
                }
            }
            return inArray;
        }

        public static byte[] desencrypt(byte[] str, byte[] key, byte[] iv, string mode = CBC)
        {
            byte[] clearData = str;
            DES desEncrypt = new DESCryptoServiceProvider();
            desEncrypt.Key = key.Take(8).ToArray();
            desEncrypt.IV = iv.Take(8).ToArray();
            desEncrypt.Mode = AesMode(mode);
            desEncrypt.Padding = PaddingMode.PKCS7;
            ICryptoTransform transForm = desEncrypt.CreateEncryptor();
            using MemoryStream encryptedStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(encryptedStream, transForm, CryptoStreamMode.Write);
            cryptoStream.Write(clearData, 0, clearData.Length);
            cryptoStream.FlushFinalBlock();
            return encryptedStream.ToArray();
        }

        public static byte[] tdesencrypt(byte[] str, byte[] key, byte[] iv, string mode = CBC)
        {
            byte[] clearData = str;

            var tdes = TripleDES.Create();
            tdes.Key = key.Take(24).ToArray();
            tdes.IV = iv.Take(8).ToArray();
            tdes.Mode = AesMode(mode);
            tdes.Padding = PaddingMode.PKCS7;
            var encryptor = tdes.CreateEncryptor();

            byte[] result;
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    cs.Write(clearData, 0, clearData.Length);

                result = ms.ToArray();
            }
            return result;
        }

        //DEC
        public static byte[] aesdecrypt(byte[] todec, byte[] key, byte[] iv, CipherMode mode)
        {
            byte[] buffer = todec;
            byte[] bytes = null;
            using (Aes aes = new AesManaged())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = mode;
                aes.Padding = PaddingMode.PKCS7;
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(buffer, 0, buffer.Length);
                        cryptoStream.Close();
                    }
                    bytes = memoryStream.ToArray();
                }
            }
            return bytes;
        }

        public static byte[] desdecrypt(byte[] todec, byte[] key, byte[] iv, CipherMode mode)
        {
            byte[] clearData = todec;
            DES desDecrypt = new DESCryptoServiceProvider();
            desDecrypt.Key = key.Take(8).ToArray();
            desDecrypt.IV = iv.Take(8).ToArray();
            desDecrypt.Mode = mode;
            desDecrypt.Padding = PaddingMode.PKCS7;
            ICryptoTransform transForm = desDecrypt.CreateDecryptor();
            MemoryStream decryptedStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(decryptedStream, transForm, CryptoStreamMode.Write);
            cryptoStream.Write(clearData, 0, clearData.Length);
            cryptoStream.FlushFinalBlock();
            return decryptedStream.ToArray();
        }

        public static byte[] tdesdecrypt(byte[] todec, byte[] key, byte[] iv, CipherMode mode)
        {

            byte[] crypt = todec;

            var tdes = TripleDES.Create();
            tdes.Key = key.Take(24).ToArray();
            tdes.IV = iv.Take(8).ToArray();
            tdes.Mode = mode;
            tdes.Padding = PaddingMode.PKCS7;

            var decryptor = tdes.CreateDecryptor();

            byte[] result;
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                    cs.Write(crypt, 0, crypt.Length);

                result = ms.ToArray();
            }

            return result;
        }
    }
    internal static class Misc
    {
        public static byte[] ToByteArray(this object obj)
        {
            return (byte[])Convert.ChangeType(obj, typeof(byte[]));
        }
    }


}
