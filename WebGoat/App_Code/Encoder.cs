using System;
using System.Collections.Generic;
using System.Web;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Data;
using System.Web.Security;

namespace OWASP.WebGoat.NET.App_Code
{
    public class Encoder
    {
        private static byte[] _salt = Encoding.ASCII.GetBytes("o6806642kbM7c5");


        public static string EncryptStringAES(string plainText, string sharedSecret)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException("plainText");
            if (string.IsNullOrEmpty(sharedSecret))
                throw new ArgumentNullException("sharedSecret");

            string outStr = null;
            RijndaelManaged aesAlg = null;

            try
            {
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, _salt);

                aesAlg = new RijndaelManaged();
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                aesAlg.IV = key.GetBytes(aesAlg.BlockSize / 8);

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            swEncrypt.Write(plainText);
                        }
                    }
                    outStr = Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
            finally
            {
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            return outStr;
        }

        public static string DecryptStringAES(string cipherText, string sharedSecret)
        {
            if (string.IsNullOrEmpty(cipherText))
                throw new ArgumentNullException("cipherText");
            if (string.IsNullOrEmpty(sharedSecret))
                throw new ArgumentNullException("sharedSecret");

            RijndaelManaged aesAlg = null;

            string plaintext = null;

            try
            {
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, _salt);

                aesAlg = new RijndaelManaged();
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                aesAlg.IV = key.GetBytes(aesAlg.BlockSize / 8);

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                byte[] bytes = Convert.FromBase64String(cipherText);
                using (MemoryStream msDecrypt = new MemoryStream(bytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))

                            plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
            finally
            {
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            return plaintext;
        }

        public static string Encode(string s)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(s);
            string output = System.Convert.ToBase64String(bytes);
            return output;
        }

        public static String Decode(string s)
        {
            byte[] bytes = System.Convert.FromBase64String(s);
            string output = System.Text.Encoding.UTF8.GetString(bytes);
            return output;
        }


        public static string ToJSONString(DataTable dt)
        {
            string[] StrDc = new string[dt.Columns.Count];

            string HeadStr = string.Empty;
            for (int i = 0; i < dt.Columns.Count; i++)
            {

                StrDc[i] = dt.Columns[i].Caption;
                HeadStr += "\"" + StrDc[i] + "\" : \"" + StrDc[i] + i.ToString() + "¾" + "\",";

            }

            HeadStr = HeadStr.Substring(0, HeadStr.Length - 1);
            StringBuilder Sb = new StringBuilder();

            Sb.Append("{\"" + dt.TableName + "\" : [");
            for (int i = 0; i < dt.Rows.Count; i++)
            {

                string TempStr = HeadStr;

                Sb.Append("{");
                for (int j = 0; j < dt.Columns.Count; j++)
                {

                    TempStr = TempStr.Replace(dt.Columns[j] + j.ToString() + "¾", dt.Rows[i][j].ToString());

                }
                Sb.Append(TempStr + "},");

            }
            Sb = new StringBuilder(Sb.ToString().Substring(0, Sb.ToString().Length - 1));

            Sb.Append("]}");
            return Sb.ToString();
        }

        public static string ToJSONSAutocompleteString(string query, DataTable dt)
        {
            char[] badvalues = { '[', ']', '{', '}'};

            foreach (char c in badvalues)
                query = query.Replace(c, '#');

            StringBuilder sb = new StringBuilder();

            sb.Append("{\nquery:'" + query + "',\n");
            sb.Append("suggestions:[");
            
            for (int i = 0; i < dt.Rows.Count; i++)
            {
                DataRow row = dt.Rows[i];
                string email = row[0].ToString();
                sb.Append("'" + email + "',");
            }
            
            sb = new StringBuilder(sb.ToString().Substring(0, sb.ToString().Length - 1));
            sb.Append("],\n");
            sb.Append("data:" + sb.ToString().Substring(sb.ToString().IndexOf('['), (sb.ToString().LastIndexOf(']') - sb.ToString().IndexOf('[')) + 1) + "\n}");

            return sb.ToString();
        }

        public string EncodeTicket(string token)
        {
            FormsAuthenticationTicket ticket =
                new FormsAuthenticationTicket(
                    1,
                    token,
                    DateTime.Now,
                    DateTime.Now.AddDays(14),
                    true,
                    "customer",
                    FormsAuthentication.FormsCookiePath
            );

            return FormsAuthentication.Encrypt(ticket);
        }

    }
}
