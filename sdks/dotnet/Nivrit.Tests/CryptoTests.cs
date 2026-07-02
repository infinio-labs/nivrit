using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Nivrit;
using Xunit;

// Hermetic crypto round-trips through the nivrit-crypto-helper binary; no API
// required. Set NIVRIT_CRYPTO_HELPER or build the helper at target/release.
public class CryptoTests
{
    private readonly HelperCrypto _c = new();

    private static string RandKeyB64() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    [Fact]
    public void HybridSuiteId() =>
        Assert.Equal("hybrid_x25519_ml_kem_768_aes256gcm_v1", _c.HybridSuiteId());

    [Fact]
    public void ValueRoundTrip()
    {
        var key = RandKeyB64();
        var enc = _c.EncryptValue("hello-dotnet", key);
        var pt = _c.DecryptValue((string)enc["ciphertext"]!, (string)enc["nonce"]!, key);
        Assert.Equal("hello-dotnet", pt);
    }

    [Fact]
    public void KeypairAndProjectKey()
    {
        const string pw = "correct horse battery staple";
        var kp = _c.GenerateKeypair(pw);
        var priv = _c.DecryptPrivateKey(
            (string)kp["encrypted_private_key"]!, (string)kp["private_key_nonce"]!, pw);

        var projectKey = RandKeyB64();
        var enc = _c.EncapsulateProjectKey(projectKey, (string)kp["public_key"]!);
        var blob = Convert.ToBase64String(Encoding.UTF8.GetBytes(enc.ToJsonString()));

        Assert.Equal(projectKey, _c.DecapsulateProjectKey(blob, priv));
    }
}
