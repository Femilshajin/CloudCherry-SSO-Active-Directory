using System;
using System.Linq;
using CloudCherrySSO.Models;
using Microsoft.Win32;
using Newtonsoft.Json;
using System.Configuration;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
namespace CloudCherrySSO.Helpers
{
    public static class SSOHelper
    {
        public static string webBaseURL = "https://cx.getcloudcherry.com/";//Web base URL
        public static string LogFolder = "Logs";//Logs Folder Name

        public static async Task<string> GetSSOTokenURL(SSOSubUser subuser)
        {
            try
            {
                if (string.IsNullOrEmpty(subuser?.ManagedBy) || string.IsNullOrEmpty(subuser?.Userid)
                    || string.IsNullOrEmpty(subuser?.SSOKey))
                {
                    WriteLog($"Default Values are not available - {subuser?.ManagedBy} {subuser?.Userid}");
                    return $"{webBaseURL}#/login?errormsg=Default values are not available - {subuser?.ManagedBy}{subuser?.Userid}";
                }

                /*
                 * If you want allow access only to users who are already available uncomment this
                if (!await CheckAPIStatus($"{subuser?.ManagedBy}{subuser?.Userid}"))
                    return $"{webBaseURL}#/login?errormsg=User not available - {subuser?.ManagedBy}{subuser?.Userid}";
                */

                string json = JsonConvert.SerializeObject(subuser);

                string token = GetSSOToken(json, subuser.ManagedBy, subuser.SSOKey);

                string signOnURL = $"{webBaseURL}#/login?sso={subuser.ManagedBy}&ssotoken={token}";

                return signOnURL;
            }
            catch (Exception ex)
            {
                WriteErrorLog(ex);
                return webBaseURL;
            }
        }

        public static async Task<bool> CheckAPIStatus(string username)
        {
            try
            {
                if (string.IsNullOrEmpty(username))
                    return false;

                string baseURL = ConfigurationManager.AppSettings["ccbaseurl"];

                WriteLog($"Checking status for {username} at {baseURL}");

                HttpClient httpClientAPIStatus = new HttpClient();
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;

                httpClientAPIStatus.Timeout = new TimeSpan(0, 0, 3); // 3 Seconds
                httpClientAPIStatus.DefaultRequestHeaders.Accept.Add(MediaTypeWithQualityHeaderValue.Parse("application/json"));
                httpClientAPIStatus.DefaultRequestHeaders.Add("User-Agent", "SSO MVC APP");
                httpClientAPIStatus.MaxResponseContentBufferSize = 64000;

                CancellationTokenSource cts = new CancellationTokenSource(3200);
                HttpResponseMessage response;
                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, $"{baseURL?.TrimEnd('/')}/api/status/{username}");
                response = await httpClientAPIStatus.SendAsync(request, cts.Token);

                if (response != null && response.IsSuccessStatusCode)
                    return true;
                else
                {
                    WriteLog($"User Not Available {username}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                WriteErrorLog(ex);
                return false;
            }
        }

        #region SSOToken Generation
        static string GetSSOToken(string roleuser, string account, string ssokey)
        {
            //Generate Initial Vector
            string strIV = InitialVector(16);
            //Generate Hashed Key
            HMACSHA256 signer = new HMACSHA256(Encoding.UTF8.GetBytes(account));
            byte[] Key = Encoding.UTF8.GetBytes(Convert.ToBase64String(signer.ComputeHash(Encoding.UTF8.GetBytes(ssokey))).Take(16).ToArray());

            byte[] encrypted = null;
            using (MemoryStream msEncrypt = new MemoryStream())
            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            {
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;
                aesAlg.Key = Key;
                aesAlg.IV = Encoding.UTF8.GetBytes(strIV);

                ICryptoTransform encryptor = aesAlg.CreateEncryptor();
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    byte[] plaintext = Encoding.UTF8.GetBytes(roleuser);
                    csEncrypt.Write(plaintext, 0, plaintext.Length);
                    csEncrypt.FlushFinalBlock();
                }
                encrypted = msEncrypt.ToArray();
            }

            string cryptedtoken = "sso-" + strIV + Convert.ToBase64String(encrypted).Replace("+", "*").Replace("=", "!");
            return HttpUtility.UrlEncode(cryptedtoken);
        }

        static string InitialVector(int maxSize)
        {
            char[] chars = new char[62];
            chars =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();
            byte[] data = new byte[1];
            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetNonZeroBytes(data);
                data = new byte[maxSize];
                crypto.GetNonZeroBytes(data);
            }
            StringBuilder result = new StringBuilder(maxSize);
            foreach (byte b in data)
            {
                result.Append(chars[b % (chars.Length)]);
            }
            return result.ToString();
        }
        #endregion

        public static string GetFrameWorkVersion()
        {
            using (RegistryKey ndpKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32).OpenSubKey("SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full\\"))
            {
                int releaseKey = Convert.ToInt32(ndpKey.GetValue("Release"));
                var version = CheckFor45DotVersion(releaseKey);
                WriteLog(version);
                return version;
            }
        }

        // Checking the version using >= will enable forward compatibility,  
        // however you should always compile your code on newer versions of 
        // the framework to ensure your app works the same. 
        private static string CheckFor45DotVersion(int releaseKey)
        {
            if (releaseKey >= 461808)
            {
                return "4.7.2 or later";
            }
            if (releaseKey >= 461308)
            {
                return "4.7.1 or later";
            }
            if (releaseKey >= 460798)
            {
                return "4.7 or later";
            }
            if (releaseKey >= 394802)
            {
                return "4.6.2 or later";
            }
            if (releaseKey >= 394254)
            {
                return "4.6.1 or later";
            }
            if (releaseKey >= 393295)
            {
                return "4.6 or later";
            }
            if (releaseKey >= 393273)
            {
                return "4.6 RC or later";
            }
            if ((releaseKey >= 379893))
            {
                return "4.5.2 or later";
            }
            if ((releaseKey >= 378675))
            {
                return "4.5.1 or later";
            }
            if ((releaseKey >= 378389))
            {
                return "4.5 or later";
            }
            // This line should never execute. A non-null release key should mean 
            // that 4.5 or later is installed. 
            return "No 4.5 or later version detected";
        }

        #region WriteLogs
        /// <summary> Writes logs </summary>
        public static void WriteLog(string Message, bool shouldNotify = true)
        {
            StreamWriter sw = null;
            try
            {
                if (!Directory.Exists(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, LogFolder)))
                {
                    Directory.CreateDirectory(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, LogFolder));
                }

                sw = new StreamWriter(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, LogFolder, DateTime.Now.ToString("dd-MM-yyyy") + " logs.txt"), true);
                sw.WriteLine(DateTime.Now.ToString() + ": " + Message);
                Console.WriteLine(DateTime.Now.ToString() + ": " + Message);
                sw.Flush();
                sw.Close();
            }
            catch { }
        }

        /// <summary> Writes Exception logs </summary>
        public static void WriteErrorLog(Exception ex)
        {
            StreamWriter sw = null;
            try
            {
                if (!Directory.Exists(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, LogFolder)))
                {
                    Directory.CreateDirectory(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, LogFolder));
                }

                sw = new StreamWriter(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, LogFolder, DateTime.Now.ToString("dd-MM-yyyy") + " logs.txt"), true);
                sw.WriteLine(DateTime.Now.ToString() + ": " + ex.Source.ToString().Trim() + "; " + ex.Message.ToString().Trim());
                sw.WriteLine(DateTime.Now.ToString() + ": " + ex);
                Console.WriteLine(DateTime.Now.ToString() + ": " + ex.Source.ToString().Trim() + "; " + ex.Message.ToString().Trim());
                sw.Flush();
                sw.Close();
            }
            catch { }
        }
        #endregion
    }
}