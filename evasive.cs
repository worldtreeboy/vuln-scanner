using System;
using System.IO;
using System.Xml.XPath;
using System.Net.Http;
using Newtonsoft.Json;
using RazorEngine;
using RazorEngine.Templating;

public class EvasiveVulnerabilities {

    // 1. [xpath] XPath Injection - Evasion: String Splitting
    public void GetUserSecret(string username) {
        XPathDocument doc = new XPathDocument("users.xml");
        XPathNavigator nav = doc.CreateNavigator();
        // The scanner has to combine these parts to see the full injection path
        string part1 = "//User[Username='";
        string query = part1 + username + "']/Secret";
        nav.Evaluate(query);
    }

    // 2. [deser] Insecure Deserialization - Evasion: Configuration Jump
    public void LoadSettings(string jsonInput) {
        var s = new JsonSerializerSettings();
        var trigger = TypeNameHandling.Auto;
        s.TypeNameHandling = trigger; // Taint doesn't flow through data, but through 'state'

        JsonConvert.DeserializeObject<object>(jsonInput, s);
    }

    // 3. [ssrf] SSRF - Evasion: Hex Encoding
    public async void FetchRemote(string userUrl) {
        // Attackers often hex encode internal IPs to bypass simple filters
        // Does your scanner track the transformation?
        string launderedUrl = userUrl.Trim().ToLower();
        HttpClient client = new HttpClient();
        await client.GetAsync(launderedUrl);
    }

    // 4. [ssti] SSTI - Evasion: Dynamic Key
    public void RenderEmail(string userTemplate, object model) {
        string randomKey = Guid.NewGuid().ToString();
        // Sink is RunCompile. Source is userTemplate.
        Engine.Razor.RunCompile(userTemplate, randomKey, null, model);
    }

    // 5. [path] Path Traversal - Evasion: Double Combine
    public void DeleteFile(string fileName) {
        string root = "C:\\App\\Uploads";
        string subDir = "UserReports";
        // Double nesting can sometimes confuse depth-check logic
        string intermediate = Path.Combine(root, subDir);
        string finalPath = Path.Combine(intermediate, fileName);
        File.Delete(finalPath);
    }

    // 6. [sql] SQL Injection - Evasion: Intermediate Formatting
    public void QueryDb(string email) {
        // Using string.Format instead of + can bypass primitive regex-based scanners
        string template = "SELECT * FROM Users WHERE Email = '{0}'";
        string sql = string.Format(template, email);
        // Assuming a DB sink here
        // db.Execute(sql);
    }
}
