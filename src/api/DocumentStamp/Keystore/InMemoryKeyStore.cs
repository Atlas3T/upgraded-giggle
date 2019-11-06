using Catalyst.Abstractions.Cryptography;
using Catalyst.Abstractions.Keystore;
using Catalyst.Abstractions.Types;
using Catalyst.Protocol.Network;
using Nethereum.KeyStore;
using System.Threading.Tasks;
using TheDotNetLeague.MultiFormats.MultiBase;

namespace DocumentStamp.Keystore
{
    public sealed class InMemoryKeyStore : KeyStoreService, IKeyStore
    {
        private ICryptoContext _cryptoContext;
        public InMemoryKeyStore(ICryptoContext cryptoContext)
        {
            _cryptoContext = cryptoContext;
        }

        public IPrivateKey KeyStoreDecrypt(KeyRegistryTypes keyIdentifier)
        {
            var privateKeyBase32 = "tbglv5xzz45cyqtp3txc5xodcx3ynkqijxvkly3te5n4uy6aokea";
            var privateKeyBytes = privateKeyBase32.FromBase32();
            return _cryptoContext.GetPrivateKeyFromBytes(privateKeyBytes);
        }

        public Task KeyStoreEncryptAsync(IPrivateKey privateKey, NetworkType networkType, KeyRegistryTypes keyIdentifier)
        {
            return Task.FromResult(KeyStoreDecrypt(keyIdentifier));
        }

        public Task<IPrivateKey> KeyStoreGenerateAsync(NetworkType networkType, KeyRegistryTypes keyIdentifier)
        {
            return Task.FromResult(KeyStoreDecrypt(keyIdentifier));
        }
    }
}
