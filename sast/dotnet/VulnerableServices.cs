using System;
using System.IO;
using System.Data.SqlClient;
using System.Runtime.Serialization.Formatters.Binary;

namespace TigerGate.Benchmark {
    public class VulnerableServices {
        public void ExecuteQuery(string userEmail) {
            using (SqlConnection conn = new SqlConnection("Server=myServerAddress;Database=myDataBase;Uid=myUsername;Pwd=myPassword;")) {
                conn.Open();
                // VULNERABLE: String concatenation into SqlCommand (CWE-89)
                string query = "SELECT Id, Name FROM Users WHERE Email = '" + userEmail + "'";
                using (SqlCommand cmd = new SqlCommand(query, conn)) {
                    using (SqlDataReader reader = cmd.ExecuteReader()) {
                        while (reader.Read()) {
                            Console.WriteLine(reader["Name"]);
                        }
                    }
                }
            }
        }

        public string ReadUserDocument(string fileName) {
            string basePath = @"C:\App\Documents";
            // VULNERABLE: Path Traversal using Path.Combine without canonical check (CWE-22)
            string fullPath = Path.Combine(basePath, fileName);
            return File.ReadAllText(fullPath);
        }

        public object DeserializePayload(Stream stream) {
            // VULNERABLE: BinaryFormatter is dangerously insecure for untrusted inputs (CWE-502)
            BinaryFormatter formatter = new BinaryFormatter();
            return formatter.Deserialize(stream);
        }
    }
}
