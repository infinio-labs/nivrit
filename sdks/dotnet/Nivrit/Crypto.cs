using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Nivrit;

public class HelperCrypto
{
    private readonly string _helperPath;

    public HelperCrypto(string? helperPath = null)
    {
        _helperPath = helperPath ?? FindHelper();
    }

    private static string FindHelper()
    {
        var env = Environment.GetEnvironmentVariable("NIVRIT_CRYPTO_HELPER");
        if (!string.IsNullOrEmpty(env)) return env;

        var extracted = ExtractFromResources();
        if (extracted != null) return extracted;

        return Path.Combine("..", "..", "..", "target", "release", "nivrit-crypto-helper");
    }

    // Extracts the platform helper embedded as a resource named
    // Nivrit.native.<rid>.nivrit-crypto-helper[.exe] (see Nivrit.csproj) to a
    // content-addressed temp path. The sha pins the binary to its bytes, so a
    // version bump never resolves a stale helper. Returns null if not bundled.
    private static string? ExtractFromResources()
    {
        var win = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        var exe = win ? "nivrit-crypto-helper.exe" : "nivrit-crypto-helper";
        var resource = $"Nivrit.native.{Rid()}.{exe}";
        var asm = Assembly.GetExecutingAssembly();
        using var stream = asm.GetManifestResourceStream(resource);
        if (stream == null) return null;

        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        var bytes = ms.ToArray();

        var sha = Convert.ToHexString(SHA256.HashData(bytes))[..16].ToLowerInvariant();
        var dir = Path.Combine(Path.GetTempPath(), "nivrit-crypto-helper", sha);
        Directory.CreateDirectory(dir);
        var target = Path.Combine(dir, exe);
        if (!File.Exists(target))
        {
            var tmp = target + ".tmp";
            File.WriteAllBytes(tmp, bytes);
            if (!win)
            {
                var psi = new ProcessStartInfo("chmod", $"700 \"{tmp}\"") { UseShellExecute = false };
                Process.Start(psi)?.WaitForExit();
            }
            File.Move(tmp, target, overwrite: true);
        }
        return target;
    }

    private static string Rid()
    {
        var os = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "win"
            : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "osx"
            : "linux";
        var arch = RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "arm64" : "x64";
        return $"{os}-{arch}";
    }

    private JsonNode Call(JsonObject req)
    {
        var psi = new ProcessStartInfo(_helperPath)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start crypto helper");
        proc.StandardInput.Write(req.ToJsonString());
        proc.StandardInput.Close();
        var output = proc.StandardOutput.ReadToEnd();
        var err = proc.StandardError.ReadToEnd();
        proc.WaitForExit();
        if (proc.ExitCode != 0)
            throw new InvalidOperationException($"crypto helper exited {proc.ExitCode}: {err}");

        var resp = JsonNode.Parse(output.Trim())!;
        if (!(bool)resp["ok"]!)
            throw new InvalidOperationException((string?)resp["error"] ?? "crypto helper error");
        return resp["result"]!;
    }

    public string HybridSuiteId() => (string?)Call(new JsonObject { ["op"] = "hybrid_suite_id" })!;

    public JsonObject GenerateKeypair(string password) =>
        (JsonObject)Call(new JsonObject { ["op"] = "generate_keypair", ["password"] = password });

    public string DecryptPrivateKey(string encryptedPrivateKey, string nonce, string password) =>
        (string?)Call(new JsonObject
        {
            ["op"] = "decrypt_private_key",
            ["encrypted_private_key"] = encryptedPrivateKey,
            ["nonce"] = nonce,
            ["password"] = password,
        })["private_key"]! ?? throw new InvalidOperationException("missing private_key");

    public string DecapsulateProjectKey(string encryptedProjectKey, string privateKey) =>
        (string?)Call(new JsonObject
        {
            ["op"] = "decapsulate_project_key",
            ["encrypted_project_key"] = encryptedProjectKey,
            ["private_key"] = privateKey,
        })["project_key"]! ?? throw new InvalidOperationException("missing project_key");

    public JsonObject EncryptValue(string plaintext, string key) =>
        (JsonObject)Call(new JsonObject { ["op"] = "encrypt_value", ["plaintext"] = plaintext, ["key"] = key });

    public string DecryptValue(string ciphertext, string nonce, string key) =>
        (string?)Call(new JsonObject
        {
            ["op"] = "decrypt_value",
            ["ciphertext"] = ciphertext,
            ["nonce"] = nonce,
            ["key"] = key,
        })["plaintext"]! ?? throw new InvalidOperationException("missing plaintext");

    public JsonObject EncapsulateProjectKey(string projectKey, string recipientPublicKey) =>
        (JsonObject)Call(new JsonObject
        {
            ["op"] = "encapsulate_project_key",
            ["project_key"] = projectKey,
            ["recipient_public_key"] = recipientPublicKey,
        });
}
