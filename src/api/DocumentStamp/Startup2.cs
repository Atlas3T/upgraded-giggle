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
using DocumentStamp;
using DocumentStamp.Keystore;
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
            //Required or it will cause outofmemory exceptions on azure functions!
            Environment.SetEnvironmentVariable("io.netty.allocator.type", "unpooled");

            var local_root = Environment.GetEnvironmentVariable("AzureWebJobsScriptRoot");
            var azure_root = $"{Environment.GetEnvironmentVariable("HOME")}/site/wwwroot";
            var actual_root = local_root ?? azure_root;

            var logger = new LoggerConfiguration().WriteTo.Debug(Serilog.Events.LogEventLevel.Debug)
                 .CreateLogger();
            var cryptoContext = new FfiWrapper();
            var keyStore = new InMemoryKeyStore(cryptoContext,
                Environment.GetEnvironmentVariable("FunctionPrivateKey"));

            var keyRegistry = new KeyRegistry();
            var keySigner = new KeySigner(keyStore, cryptoContext, keyRegistry);

            var memoryCacheOptions = new MemoryCacheOptions();
            var memoryCache = new MemoryCache(memoryCacheOptions);
            var changeTokenProvider = new TtlChangeTokenProvider(10000);
            var messageCorrelationManager =
                new RpcMessageCorrelationManager(memoryCache, logger, changeTokenProvider);
            var peerIdValidator = new PeerIdValidator(cryptoContext);

            var privateKey = keyRegistry.GetItemFromRegistry(KeyRegistryTypes.DefaultKey);
            var publicKey = privateKey.GetPublicKey();
            var publicKeyBase32 = publicKey.Bytes.ToBase32();

            var peerConfig = new Dictionary<string, string>
                {
                    {"CatalystNodeConfiguration:Peer:Network", "Devnet"},
                    {"CatalystNodeConfiguration:Peer:PublicKey", publicKeyBase32},
                    {"CatalystNodeConfiguration:Peer:Port", "42076"},
                    {"CatalystNodeConfiguration:Peer:PublicIpAddress", IPAddress.Loopback.ToString()},
                    {"CatalystNodeConfiguration:Peer:BindAddress", IPAddress.Loopback.ToString()}
                };

            var peerSettingsConfig = new ConfigurationBuilder().AddInMemoryCollection(peerConfig).Build();
            var peerSettings = new PeerSettings(peerSettingsConfig);

            var rpcClientSettings = new RpcClientSettings
            {
                HostAddress = IPAddress.Parse(Environment.GetEnvironmentVariable("NodeIpAddress")),
                Port = int.Parse(Environment.GetEnvironmentVariable("NodePort")),
                PublicKey = Environment.GetEnvironmentVariable("NodePublicKey")
            };

            var recipientPeer =
                rpcClientSettings.PublicKey.BuildPeerIdFromBase32Key(rpcClientSettings.HostAddress,
                    rpcClientSettings.Port);

            var nodeRpcClientChannelFactory =
                new RpcClientChannelFactory(keySigner, messageCorrelationManager, peerIdValidator, peerSettings, 0);

            var eventLoopGroupFactoryConfiguration = new EventLoopGroupFactoryConfiguration
            {
                TcpClientHandlerWorkerThreads = 4
            };

            var tcpClientEventLoopGroupFactory =
                new TcpClientEventLoopGroupFactory(eventLoopGroupFactoryConfiguration);
            var handlers = new List<IRpcResponseObserver>
                {
                    new BroadcastRawTransactionResponseObserver(logger)
                };

            var rpcClientFactory = new RpcClientFactory(nodeRpcClientChannelFactory,
                tcpClientEventLoopGroupFactory, handlers);

            var certBytes = File.ReadAllBytes(Path.Combine(actual_root,
                Environment.GetEnvironmentVariable("NodePfxFileName")));

            var certificate = new X509Certificate2(certBytes,
                Environment.GetEnvironmentVariable("NodeSslCertPassword"),
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet |
                X509KeyStorageFlags.Exportable);

            var rpcClient = rpcClientFactory.GetClient(certificate, rpcClientSettings).Result;

            var restClient = new RestClient(Environment.GetEnvironmentVariable("NodeWebAddress"));
            builder.Services.AddSingleton(restClient);
            builder.Services.AddSingleton(rpcClient);
            builder.Services.AddSingleton(peerSettings);
            builder.Services.AddSingleton(cryptoContext);
            builder.Services.AddSingleton(privateKey);
            builder.Services.AddSingleton(recipientPeer);
        }
    }
}