using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace EncryptionClassLibrary
{
    public class GetToken
    {
        public string GetStringToken()
        {
            try
            {
                string path =@"C:\Users\John\Desktop\Token.txt";
                return File.ReadAllText(path);
            }
            catch 
            {
                return "Error reading file";
            }
            
        }
    }
}
