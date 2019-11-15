using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Catalyst.Abstractions.IO.Observers;
using Catalyst.Abstractions.Types;
using Catalyst.Core.Lib.Cryptography;
using Catalyst.Core.Lib.Extensions;
using Catalyst.Core.Lib.IO.EventLoop;
using Catalyst.Core.Lib.P2P;
using Catalyst.Core.Lib.Rpc.IO.Messaging.Correlation;
using Catalyst.Core.Lib.Util;
using Catalyst.Core.Modules.Cryptography.BulletProofs;
using Catalyst.Core.Modules.KeySigner;
using Catalyst.Core.Modules.Rpc.Client;
using Catalyst.Core.Modules.Rpc.Client.IO.Observers;
using Catalyst.Core.Modules.Rpc.Client.IO.Transport.Channels;
using Catalyst.Modules.Repository.CosmosDb;
using DocumentStamp;
using DocumentStamp.Keystore;
using DocumentStamp.Model;
using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using RestSharp;
using Serilog;
using TheDotNetLeague.MultiFormats.MultiBase;

[assembly: FunctionsStartup(typeof(Startup))]

namespace DocumentStamp
{
    public class Startup : FunctionsStartup
    {
        public override void Configure(IFunctionsHostBuilder builder)
        {
            var cryptoContext = new FfiWrapper();
            var keyStore = new InMemoryKeyStore(cryptoContext,
                Environment.GetEnvironmentVariable("FunctionPrivateKey"));

            var keyRegistry = new KeyRegistry();
            var keySigner = new KeySigner(keyStore, cryptoContext, keyRegistry);

            var privateKey = keyRegistry.GetItemFromRegistry(KeyRegistryTypes.DefaultKey);
            var publicKey = privateKey.GetPublicKey();
            var publicKeyBase32 = publicKey.Bytes.ToBase32();

            var peerId = publicKeyBase32.BuildPeerIdFromBase32Key(IPAddress.Loopback, 42076);

            var recptIp = IPAddress.Parse(Environment.GetEnvironmentVariable("NodeIpAddress"));
            var recptPort = int.Parse(Environment.GetEnvironmentVariable("NodePort"));
            var recptPublicKey = Environment.GetEnvironmentVariable("NodePublicKey");

            var recipientPeer =
                recptPublicKey.BuildPeerIdFromBase32Key(recptIp,
                    recptPort);

            var documentStampMetaDataRepository = new CosmosDbRepository<DocumentStampMetaData>("https://localhost:8081", "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==", "mempool", true);

            var restClient = new RestClient(Environment.GetEnvironmentVariable("NodeWebAddress"));
            builder.Services.AddSingleton(restClient);
            builder.Services.AddSingleton(peerId);
            builder.Services.AddSingleton(cryptoContext);
            builder.Services.AddSingleton(privateKey);
            builder.Services.AddSingleton(recipientPeer);
            builder.Services.AddSingleton(documentStampMetaDataRepository);
        }
    }
}