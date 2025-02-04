using Org.BouncyCastle.Asn1.Cms;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml.Linq;

namespace Cryptograpgy
{
    internal class Program
    {
        static string ENCDir = String.Concat(Directory.GetCurrentDirectory(), @"\Encrypted");
        static string DECDir = String.Concat(Directory.GetCurrentDirectory(), @"\Decrypted");
        static string HASDir = String.Concat(Directory.GetCurrentDirectory(), @"\Hashed");
        static byte[] FileData;
        static string ext = "";
        static string fname = "";
        static byte[] purePass;
        /// <summary>
        /// First Byte -> 0: Hash, 1: Encryption
        /// Second Byte -> 0: AES, 1: DES, 2: 3DES, 3: RSA
        /// Third Byte -> 0: CBC, 1: ECB, 2: OBF, 3: CFB
        /// <!--Forth Byte -> Seperator : "|"-->
        /// </summary>
        static byte[] InfoBytes = new byte[3];
        static byte Zero = Encoding.UTF8.GetBytes("0")[0];
        static byte One = Encoding.UTF8.GetBytes("1")[0];
        static byte Two = Encoding.UTF8.GetBytes("2")[0];
        static byte Three = Encoding.UTF8.GetBytes("3")[0];

        static bool inpFile = false;
        static List<string> algos = new List<string>();

        [STAThread]
        static void Main(string[] args)
        {
            Console.Title = "CryptoGraphy | Ayush | Akshay | Khushi";
            Console.WriteLine(">> Welcome to presentation of Cryptography Interface.");
        ReStart:
            InfoBytes[0] = Zero; InfoBytes[1] = Zero; InfoBytes[2] = Zero;
            Directory.CreateDirectory(ENCDir);
            Directory.CreateDirectory(DECDir);
            Directory.CreateDirectory(HASDir);
            Console.WriteLine(">> Select an Approach: ");
        ReMeth:
            Console.WriteLine(" 1. Hash\n 2. Encrypt\n 3. Decrypt");
            Console.Write(" > ");
            int methOpt = int.Parse(Console.ReadLine());
            if (methOpt == 1 || methOpt == 2)
            {
                Console.WriteLine(">> How would you like to Input your Data?");
            ReinOpt:
                Console.Write(" 1. Text\n 2. File\n > ");
                int inOpt = int.Parse(Console.ReadLine());
                byte[] inData;
                byte[] outData;
                switch (inOpt)
                {
                case 1:
                        Console.WriteLine(">> Enter Data: ");
                        Console.Write(" > ");
                        inData = Encoding.UTF8.GetBytes(Console.ReadLine());
                        ext = "txt";
                        fname = Functions.rand();
                        break;
                case 2:
                    ReCase2:
                        inpFile = true;
                        Console.WriteLine(">> Select File: ");
                        Thread.Sleep(1000);
                        OpenFileDialog configaddDLOG = new OpenFileDialog
                        {
                            Title = "Select Any File",
                            Filter = "All files (*.*)|*.*",
                            Multiselect = false
                        };
                        if (configaddDLOG.ShowDialog() == DialogResult.OK)
                        {
                            inData = File.ReadAllBytes(configaddDLOG.FileName);
                            string name = configaddDLOG.SafeFileName;
                            ext = Path.GetExtension(name);
                            fname = Path.GetFileNameWithoutExtension(name);
                        }
                        else
                        {
                            Console.WriteLine(" !! NO FILE SELECTED. PLEASE SELECT A FILE");
                            goto ReCase2;
                        }
                        break;
                default:
                        Console.WriteLine(" !! SELECT A VALID OPTION");
                        goto ReinOpt;
                }

                //ENC BEGIN
                if(methOpt == 1)
                {
                ReHashOpt:
                    Console.WriteLine(">> Select an Algo: ");
                    Console.WriteLine(" 1. MD5\n 2. SHA1\n 3. SHA256");
                    Console.Write(" > ");
                    int hashopt = int.Parse(Console.ReadLine());
                    byte[] toutData;
                    switch (hashopt)
                    {
                        case 1:
                            toutData = Functions.md5(inData);
                            break;
                        case 2:
                            toutData = Functions.sha1(inData);
                            break;
                        case 3:
                            toutData = Functions.sha256(inData);
                            break;
                        default:
                            goto ReHashOpt;
                    }
                    byte[] t2outData = Functions.arraydump(InfoBytes, toutData);
                    outData = Functions.arraydump(Encoding.UTF8.GetBytes("1"),Functions.Compress(t2outData));
                    fname = Functions.rand();
                    File.WriteAllBytes(Path.Combine(HASDir,fname+".ak"), outData);
                    Console.WriteLine(" ** Hashed and Saved as "+fname+".ak! **");
                    Console.ReadKey();
                    Console.Clear();
                    goto ReStart;
                }
                else if(methOpt == 2)
                {
                    Console.Write(" > Enter a Password: ");
                    purePass = Encoding.UTF8.GetBytes(Console.ReadLine());
                    int count = 0;
                    List<byte[]> allOutData = new List<byte[]>();
                    allOutData.Add(inData);
                ReENC:
                    Console.WriteLine(">> Select an Algo: ");
                    Console.WriteLine(" 1. AES\n 2. DES\n 3. 3DES");
                    Console.Write(" > ");
                    int encopt = int.Parse(Console.ReadLine());
                    string nestOpt = "N";

                    switch (encopt)
                    {
                        case 1:
                            count++;
                            byte[] aespass = Functions.sha256(purePass);
                            byte[] aesiv = Functions.md5(purePass);
                        ReAES:
                            Console.WriteLine(">> Select Mode: ");
                            Console.WriteLine(" 1. CBC\n 2. ECB\n 3. OBF");
                            Console.Write(" > ");
                            int aesmodeopt = int.Parse(Console.ReadLine());
                            switch(aesmodeopt)
                            {
                                case 1:
                                    InfoBytes[0] = One;
                                    InfoBytes[1] = Zero;
                                    InfoBytes[2] = Zero;
                                    allOutData.Add(Functions.arraydump(InfoBytes,Functions.aesencrypt(allOutData.Last(), aespass, aesiv, "CBC")));
                                    break;
                                case 2:
                                    InfoBytes[0] = One;
                                    InfoBytes[1] = Zero;
                                    InfoBytes[2] = One;
                                    allOutData.Add(Functions.arraydump(InfoBytes, Functions.aesencrypt(allOutData.Last(), aespass, aesiv, "ECB")));
                                    break;
                                case 3:
                                    InfoBytes[0] = One;
                                    InfoBytes[1] = Zero;
                                    InfoBytes[2] = Two;
                                    allOutData.Add(Functions.arraydump(InfoBytes, Functions.aesencrypt(allOutData.Last(), aespass, aesiv, "OBF")));
                                    break;
                                //case 4:
                                //    InfoBytes[0] = One;
                                //    InfoBytes[1] = Zero;
                                //    InfoBytes[2] = Three;
                                //    allOutData.Add(Functions.arraydump(InfoBytes, Functions.aesencrypt(allOutData.Last(), aespass, aesiv, "CFB")));
                                //    break;
                                default:
                                    Console.WriteLine(" !! SELECT A VALID OPTION");
                                    goto ReAES;
                            }
                            Console.Write(" ?? Nest Encryption? [Y/N] ");
                            nestOpt = Console.ReadLine();
                            if (nestOpt.ToUpper() == "Y")
                                goto ReENC;
                            break;

                        case 2:
                            count++;
                            byte[] despass = Functions.sha256(purePass);
                            byte[] desiv = Functions.md5(purePass);
                        ReDES:
                            Console.WriteLine(">> Select Mode: ");
                            Console.WriteLine(" 1. CBC\n 2. ECB\n 3. CFB");
                            Console.Write(" > ");
                            int desmodeopt = int.Parse(Console.ReadLine());
                            switch (desmodeopt)
                            {
                                case 1:
                                    InfoBytes[0] = One;
                                    InfoBytes[1] = One;
                                    InfoBytes[2] = Zero;
                                    allOutData.Add(Functions.arraydump(InfoBytes, Functions.desencrypt(allOutData.Last(), despass, desiv, "CBC")));
                                    break;
                                case 2:
                                    InfoBytes[0] = One;
                                    InfoBytes[1] = One;
                                    InfoBytes[2] = One;
                                    allOutData.Add(Functions.arraydump(InfoBytes, Functions.desencrypt(allOutData.Last(), despass, desiv, "ECB")));
                                    break;
                                //case 3:
                                //    InfoBytes[0] = One;
                                //    InfoBytes[1] = One;
                                //    InfoBytes[2] = Two;
                                //    allOutData.Add(Functions.arraydump(InfoBytes, Functions.desencrypt(allOutData.Last(), despass, desiv, "OBF")));
                                //    break;
                                case 3:
                                    InfoBytes[0] = One;
                                    InfoBytes[1] = One;
                                    InfoBytes[2] = Three;
                                    allOutData.Add(Functions.arraydump(InfoBytes, Functions.desencrypt(allOutData.Last(), despass, desiv, "CFB")));
                                    break;
                                default:
                                    Console.WriteLine(" !! SELECT A VALID OPTION");
                                    goto ReDES;
                            }
                            Console.Write(" ?? Nest Encryption? [Y/N] ");
                            nestOpt = Console.ReadLine();
                            if (nestOpt.ToUpper() == "Y")
                                goto ReENC;
                            break;

                        case 3:
                            count++;
                            byte[] tdespass = Functions.sha256(purePass);
                            byte[] tdesiv = Functions.md5(purePass);
                        Re3DES:
                            Console.WriteLine(">> Select Mode: ");
                            Console.WriteLine(" 1. CBC\n 2. ECB\n 3. CFB");
                            Console.Write(" > ");
                            int tdesmodeopt = int.Parse(Console.ReadLine());
                            switch (tdesmodeopt)
                            {
                                case 1:
                                    InfoBytes[0] = One;
                                    InfoBytes[1] = Two;
                                    InfoBytes[2] = Zero;
                                    allOutData.Add(Functions.arraydump(InfoBytes, Functions.tdesencrypt(allOutData.Last(), tdespass, tdesiv, "CBC")));
                                    break;
                                case 2:
                                    InfoBytes[0] = One;
                                    InfoBytes[1] = Two;
                                    InfoBytes[2] = One;
                                    allOutData.Add(Functions.arraydump(InfoBytes, Functions.tdesencrypt(allOutData.Last(), tdespass, tdesiv, "ECB")));
                                    break;
                                case 3:
                                    InfoBytes[0] = One;
                                    InfoBytes[1] = Two;
                                    InfoBytes[2] = Three;
                                    allOutData.Add(Functions.arraydump(InfoBytes, Functions.tdesencrypt(allOutData.Last(), tdespass, tdesiv, "CFB")));
                                    break;
                                default:
                                    Console.WriteLine(" !! SELECT A VALID OPTION");
                                    goto Re3DES;
                            }
                            Console.Write(" ?? Nest Encryption? [Y/N] ");
                            nestOpt = Console.ReadLine();
                            if (nestOpt.ToUpper() == "Y")
                                goto ReENC;
                            break;

                        default:
                            Console.WriteLine(" !! SELECT A VALID OPTION");
                            goto ReENC;
                    }

                    File.WriteAllBytes(Path.Combine(ENCDir,fname+".ak"), Functions.arraydump(Encoding.UTF8.GetBytes(count.ToString()), Encoding.UTF8.GetBytes(ext+"|"), Functions.Compress(allOutData.Last())));
                    Console.WriteLine(" ** Encrypted and Saved as " + fname + ".ak! **");
                    Console.ReadKey();
                    Console.Clear();
                    goto ReStart;
                }
            }
            else if(methOpt == 3)
            {
                Console.WriteLine(">> Select File to Decrypt: ");
                Thread.Sleep(1000);
                byte[] inData;
            ReUpoad:
                OpenFileDialog configaddDLOG = new OpenFileDialog
                {
                    Title = "Select AK File",
                    Filter = "ak files (*.ak)|*.ak",
                    Multiselect = false
                };
                if (configaddDLOG.ShowDialog() == DialogResult.OK)
                {
                    inData = File.ReadAllBytes(configaddDLOG.FileName);
                    string name = configaddDLOG.SafeFileName;
                    fname = Path.GetFileNameWithoutExtension(name);
                }
                else
                {
                    Console.WriteLine(" !! NO FILE SELECTED. PLEASE SELECT A FILE");
                    goto ReUpoad;
                }
                int dotIndex = Array.IndexOf(inData, (byte)0x2e);
                int slashIndex = Array.IndexOf(inData, (byte)0x7c);
                int count = int.Parse(Encoding.UTF8.GetString(inData.Take(dotIndex).ToArray()));
                ext = Encoding.UTF8.GetString(inData.Skip(dotIndex).Take(slashIndex-dotIndex).ToArray());
                byte[] encData = Functions.Decompress(inData.Skip(slashIndex+1).Take(inData.Length - slashIndex + 1).ToArray());
                List<byte[]> allOutData = new List<byte[]>
                {
                    encData
                };
                Console.Write(" > Enter your Password: ");
                purePass = Encoding.UTF8.GetBytes(Console.ReadLine());
                while (count > 0)
                {
                    count--;
                    byte[] toutData = allOutData.Last();
                    int encHash = int.Parse(Encoding.UTF8.GetString(new byte[] { toutData[0] }));
                    int encType = int.Parse(Encoding.UTF8.GetString(new byte[] { toutData[1] }));
                    int encMode = int.Parse(Encoding.UTF8.GetString(new byte[] { toutData[2] }));
                    CipherMode mode = Functions.AesMode(encMode);
                    switch(encHash)
                    {
                        case 0:
                            Console.WriteLine(" !! CANNOT DECRYPT HASH");
                            break;
                        case 1:
                            byte[] key = Functions.sha256(purePass);
                            byte[] iv = Functions.md5(purePass);
                            switch(encType)
                            {
                                case 0:
                                    allOutData.Add(Functions.aesdecrypt(toutData.Skip(3).ToArray(), key, iv, mode));
                                    break;
                                case 1:
                                    allOutData.Add(Functions.desdecrypt(toutData.Skip(3).ToArray(), key, iv, mode));
                                    break;
                                case 2:
                                    allOutData.Add(Functions.tdesdecrypt(toutData.Skip(3).ToArray(), key, iv, mode));
                                    break;
                                default:
                                    break;
                            }
                            break;
                    }
                }
                File.WriteAllBytes(Path.Combine(DECDir, fname + ext), allOutData.Last());
                Console.WriteLine("File Successfully Decrypted and Saved as "+fname+ext);
                Console.ReadKey();
                Console.Clear();
                goto ReStart;
            }
            else
            {
                goto ReMeth;
            }

            Console.Read();

        }
    }
}
