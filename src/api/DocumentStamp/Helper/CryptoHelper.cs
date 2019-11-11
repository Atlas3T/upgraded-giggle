using System;
using Catalyst.Abstractions.Cryptography;
using Catalyst.Core.Modules.Cryptography.BulletProofs;

namespace DocumentStamp.Helper
{
    public static class CryptoHelper
    {
        private static readonly Lazy<ICryptoContext> CryptoContext =
            new Lazy<ICryptoContext>(() => new FfiWrapper());

        public static ICryptoContext GetCryptoContext()
        {
            return CryptoContext.Value;
        }
    }
}
