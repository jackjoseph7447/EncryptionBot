namespace Project5.Models
{
    using System;
    using Konscious.Security.Cryptography;
    using System.Linq;
    using System.Text;

    //for discord
    using Discord;
    using Discord.WebSocket;
    using System.Threading.Tasks;

    public class PasswordHasher
    {
        private readonly int DegreeOfParallelism = 8;
        private readonly int MemorySize = 65536;
        private readonly int Iterations = 4;
        private const string Token = "MTE4NTA4NDQ3MTQzNTg3MDI0OQ.GvHwvv.j7M_vTAWDQh9LXPioZZeeyhyqyRTPLPhUM2n-Y"; //Discord Bot Token

        private DiscordSocketClient client;

        static void Main() => new PasswordHasher().RunBotAsync().GetAwaiter().GetResult();

        public async Task RunBotAsync()
        {
            client = new DiscordSocketClient();
            client.Log += Log;

            //await RegisterCommandsAsync();

            await client.LoginAsync(TokenType.Bot, Token);

            await client.StartAsync();

            await Task.Delay(-1);
        }

        private Task Log(LogMessage arg)
        {
            Console.WriteLine(arg);
            return Task.CompletedTask;
        }

        public string HashPassword(string password)
        {
            // Generate a random salt
            byte[] salt = new byte[16];
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }

            // Convert the string password to a byte array
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

            // Hash the password using Argon2
            using (var hasher = new Argon2id(passwordBytes))
            {
                hasher.Salt = salt;
                hasher.DegreeOfParallelism = DegreeOfParallelism;
                hasher.MemorySize = MemorySize; // in KB. This size allows for it to be more expensive tech wise to try and crack the hash
                hasher.Iterations = Iterations; //This also helps with the slowing process of brute-force attacks.
                                                //typically, this number can be as high as thousands or tens of thousands.

                byte[] hash = hasher.GetBytes(32); // 32-byte hash
                byte[] hashWithSalt = salt.Concat(hash).ToArray();

                return Convert.ToBase64String(hashWithSalt);
            }
        }

        public bool VerifyPassword(string password, string hashedPassword)
        {
            try
            {
                // get salt and hash from stored password
                byte[] hashWithSalt = Convert.FromBase64String(hashedPassword);

                // get hash size
                int hashSize = 32; //from hash in HashPassword

                // makes sure the array is long enough
                if (hashWithSalt.Length < 16 + hashSize)
                {
                    return false;
                }

                // get stored hash from hashWithSalt array
                byte[] storedHash = new byte[hashSize];
                Array.Copy(hashWithSalt, 16, storedHash, 0, hashSize);

                // make string password to byte array
                byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

                // Hash the provided password using the stored salt
                using (var hasher = new Argon2id(passwordBytes))
                {
                    byte[] salt = hashWithSalt.Take(16).ToArray();

                    hasher.Salt = salt;
                    hasher.DegreeOfParallelism = DegreeOfParallelism;
                    hasher.MemorySize = MemorySize;
                    hasher.Iterations = Iterations;

                    byte[] newHash = hasher.GetBytes(hashSize); // Adjust this size based on your hash size

                    // Compare the stored hash with the newly generated hash
                    return newHash.SequenceEqual(storedHash);
                }
            }
            catch (Exception)
            {
                // Handle the exception appropriately (log, rethrow, etc.)
                return false;
            }
        }
    }
}
