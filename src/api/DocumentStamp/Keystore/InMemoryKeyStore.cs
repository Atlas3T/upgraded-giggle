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
        private string _privateKey;
        private ICryptoContext _cryptoContext;
        public InMemoryKeyStore(ICryptoContext cryptoContext, string privateKey)
        {
            _cryptoContext = cryptoContext;
            _privateKey = privateKey;
        }

        public IPrivateKey KeyStoreDecrypt(KeyRegistryTypes keyIdentifier)
        {
            var privateKeyBytes = _privateKey.FromBase32();
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
