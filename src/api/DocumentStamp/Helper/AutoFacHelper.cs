using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using Autofac;
using Autofac.Configuration;
using Catalyst.Abstractions.Cli;
using Catalyst.Abstractions.Cryptography;
using Catalyst.Abstractions.IO.Observers;
using Catalyst.Abstractions.Keystore;
using Catalyst.Abstractions.P2P;
using Catalyst.Abstractions.Rpc;
using Catalyst.Abstractions.Types;
using Catalyst.Core.Lib;
using Catalyst.Core.Lib.Cli;
using Catalyst.Core.Lib.Cryptography;
using Catalyst.Core.Lib.P2P;
using Catalyst.Core.Modules.Cryptography.BulletProofs;
using Catalyst.Core.Modules.Hashing;
using Catalyst.Core.Modules.KeySigner;
using Catalyst.Core.Modules.Keystore;
using Catalyst.Core.Modules.Rpc.Client;
using Catalyst.Core.Modules.Rpc.Client.IO.Observers;
using DocumentStamp.Keystore;
using DocumentStamp.Model;
using Microsoft.Extensions.Configuration;
using Serilog;
using TheDotNetLeague.MultiFormats.MultiBase;

namespace DocumentStamp.Helper
{
    public static class AutoFacHelper
    {
        public static ContainerBuilder GenerateRpcClientContainerBuilder()
        {
            var local_root = Environment.GetEnvironmentVariable("AzureWebJobsScriptRoot");
            var azure_root = $"{Environment.GetEnvironmentVariable("HOME")}/site/wwwroot";
            var actual_root = local_root ?? azure_root;
            //ExecutionContext.FunctionAppDirectory;
            var configRoot = new ConfigurationBuilder()
                .AddJsonFile(Path.Combine(actual_root, "config.json")).Build();
            var configModule = new ConfigurationModule(configRoot);

            var containerBuilder = new ContainerBuilder();
            containerBuilder.RegisterModule(configModule);
            containerBuilder.RegisterInstance(configRoot).As<IConfigurationRoot>();

            containerBuilder.RegisterType<Config>();
            containerBuilder.RegisterType<ConsoleUserOutput>().As<IUserOutput>();
            containerBuilder.RegisterType<ConsoleUserInput>().As<IUserInput>();
            containerBuilder.RegisterInstance(new LoggerConfiguration().WriteTo.Debug(Serilog.Events.LogEventLevel.Debug).CreateLogger()).As<ILogger>();
            containerBuilder.RegisterModule<CoreLibProvider>();
            containerBuilder.RegisterModule<RpcClientModule>();
            containerBuilder.RegisterModule<KeySignerModule>();
            containerBuilder.RegisterModule<KeystoreModule>();
            containerBuilder.RegisterModule<BulletProofsModule>();
            containerBuilder.RegisterModule<HashingModule>();

            containerBuilder.RegisterType<InMemoryKeyStore>().As<IKeyStore>().SingleInstance();

            RegisterPasswordRegistry(containerBuilder);
            RegisterCertificate(containerBuilder, actual_root);
            RegisterPeerSettings(containerBuilder);
            RegisterRpcClientSettings(containerBuilder, actual_root);
            RegisterRpcResponseObservers(containerBuilder);

            return containerBuilder;
        }

        private static void RegisterPasswordRegistry(ContainerBuilder containerBuilder)
        {
            containerBuilder.Register(x =>
            {
                var config = x.Resolve<Config>();
                var passwordRegistry = new PasswordRegistry();
                var secureString = new SecureString();
                config.NodeConfig.NodePassword.ToCharArray().ToList().ForEach(secureString.AppendChar);
                passwordRegistry.AddItemToRegistry(PasswordRegistryTypes.DefaultNodePassword, secureString);
                return passwordRegistry;
            }).As<IPasswordRegistry>();
        }

        private static void RegisterRpcResponseObservers(ContainerBuilder containerBuilder)
        {
            containerBuilder.RegisterType<BroadcastRawTransactionResponseObserver>().As<IRpcResponseObserver>();
        }

        private static void RegisterCertificate(ContainerBuilder containerBuilder, string path)
        {
            containerBuilder.Register(x =>
            {
                var config = x.Resolve<Config>();
                var filePath = Path.Combine(path, config.NodeConfig.PfxFileName);
                var cert32 = "gcbat6acaebtbaqjwqdaskugjcdpodiba4a2baqjuuciecnbgcbathjqqic64bqjfkderbxxbuaqoanaqic56becaxntbaqf24yiebotayfsvbsiq33q2aimbiaqfiecatxdbaqe5iybybqkfkderbxxbuaqyaidgahaichbbwgq34v6d6raeaqh2aciebgibw7r44pw4pcewcjunxaq2ahracwaeq56bi5y6346phrwt3omb27zj72h43s5iijc4gunzowpby25b7op4oz5u745bc7mip7w4g6hxpg6j4gfnvgxpgun6nsj77fehbcq5npxfg4i6rsrmpxwrgukg6yejg64e6u5u3uqkn3a67yxn6f7szue5ra3c4zygdh2zdop6qv2y4aj5z3ttrmkonw23zo3acifgixnvteastr66i6isxrw5v3fbgav7yelv4enk6fdliab257l5t7y2kdvkoyrikclgwyuis6bonqkqyp2m2m4ipniggcwtxqkiqtuakzuhkk46tbdilhttmkp6umewv6i7xiirlw6p2w5amgy4jlref6nwzb7ecuf6i2glw5iqo4uo5ca634iiew62gf3fhtwajjt3npvipslbvvkcd26urtjodbet2tgn6dilp6pkvvdh3kwul5nte57mop34mzdd53lfs6wqyr6zqgyj6siy3ezleiuowilsfvnqqmmgolfnz75xtr6i3e25cbf6wflvsldhs46lkwzdiblqcz5kxalxxyylnfbb2gh2m7vuzf66sidqxwskaqz3pms25hb5d2q2re4lubccobiprumaq3up3vch4iqkyyrtunnwj4wm4qtmwr66pg4qs4n4oe5zbr3dtwllotrybbdziihrv7kqj3pccsbbv4cfwd344kqxjxmxl3grnosbxsenpnjfwuzbecuw4wgwdcinebwivx57dkuwy2akpbau6okzix33ipilnhs4n6z3boiv26tfqseaiuwqusw2matftyjlcj6df27m7s7ldgg5hwxfj3jgn3t5xvbbiyhtozf775hiwo6krkdycokff5ucoxujqmzkjcqigqlvy6cmrazlgf65tsjk5jhpz7ni4zvc5myiknkrayqz5f6datiaergb2x4lotdkfd23rkam3lx4j6e3ii36j3jrcjwzhnnnmr74epvd7riup5df3d6i4hpalns6goy2j472rjn7t42fj534gwyibgydoizlkkmf4esnwyz3ynisbfxew77hr4gruxdt3xtqpujb52qzbvuoypcqbqnxannjlfxjkrc5b74awldmef5wu7h3fjsprnci3bvondh5tiwr4vx4ca36k46k6k6ek4op3m2lc7yi6ieytte2nm6huwytjpjfa6yisyd4g7q2nbia4nzqdjkvpwf2evlbtwppnveslxho3k6gjv7roim5beeqr7itbpnbdmufjtw46jfnacsvqleyjiftnth5k5bwt6cz2knfm5j3mxghan2oyztfrmd3uknt5ne4tihlmxzzqhvaakdqfjg2mtx7h3gpkzgwiqx7gb4rammtr3aevcmzypdzol3hvjg4xrcy67zn5lkhcq32a5sgq62isgaccb4nwfogj7qq2ngldlfaa2hiybvjm4wntg7egnolrimd6twwelv5rzdnanmouplcqtoj2do33ez5gmkyfbwq5guxqdz4cwc424hugmk7g4cryq5i5aprlmp2nmvx3rovcq5nthz2me7rrg3orvsh4bydiqu5ezcb6632mgsi6ljqjqfwzwryytnuwsypsmk3g3i274haqvmcfvbxopdscvp32upxm3vsjyjhumbwd3bwnchh5wsdi26sqyghifbpozhg3kkhutd7lmfcgq5ntio2se3yugb4qrqqv3fkjxs2tb65hmalbf7wbxfjhfqn25vz5ynthd7dmofxj43ti3bbiegy2b24bqentgagmoozgrhwddlpb6djqp3riadi5amsgoq5gb4xw6y5gkuuearnp2fgea7vo2o54asi2r6d6nxhxfrmx7l2oblkmwsavw4xyg6tja5pvuwto7dvc3gjhwclaqsoipwdqrocxe3urgtm6yzwswysf7zyqzcoe6vdz2kgtaigiqgbebrqhitaeygbevimseg64gqccivgedaibabaaaaamc3ayesvbsiq33q2aijcqyu4hsmab5qamiageadeacgabbaaqyaiqadsabnabbaaqqaieadsabnaa2aamyaiiaeeabnaa4aaqyagmaemabnaa3qaraaguadoabraa4qanqageaekacdaa4qaniapuyf2bqjfmdacbabqi3rcajrkape4acnabuqayyaoiag6adtabxqazqaoqacaactabxqazqaoqahoadbabzaaziaeaaewadfab4qaiaakmahiadpabzaayiam4agkabaabiaa4qan4ahmadjabsaaziaoiyiea5hayesvbsiq33q2aiha2qiea4ygcbahfacaeadbaqdrudaskugjcdpodiba4atahagbivimseg64gqcdabamya4baiov3rvkzbpjw4caqca7iibaqdmd2ctgsnisckm7ubmlm56sopvmmzm2nw7xi2mvosryqrkoz7x6eitupiosyeosnmj7l3qlzqslwhrrfyw6rplp4ztnscserngd7ntxfuq57adb7kufyybdofc6atgozvp2hm7pn5l7sgwyn2d7pkzt7wwqvsvkoqixadkj7dcg3whcg2r7b2243qvsj4s2xxauhnuk4qe3b2vuvf5tcujztxg5tndxsrnm22jczfokctbr6kjn7mkuamo6edg7cfxkczhqscog26hb2g4s3ev7zkgy7odnjgmivxcppbyqg3tkbyael3l4rrhephbghtgj32h3vrwrrnay6sy35cvlv42j5jmkcvfc6fc4onfwqd2shqfrc7nkrhug7lamiugjm2geww5jjx4udjtvmq7zfqjonayrvgv5y2urm5hnyebmz6ydqxffu7rtf2jxoxxcclhucmzmhmmnis65wrsjmzhrxxt5m7cnypg3zgbjcpfh73x255zv2bpzonkcudgmaf2yunji4rws5ie6y7fd6acvw73m6hz4ifovpe5tqlrkk3tukwebrh56lkz4eojxfxpwk4taoo3iqdsaqqtv726pfruonnrovez3nu3hryfhi5qqhajvjutmtvl5qm62vpwqtrvxmhiwfwt5hffusabo77ccrvfqa4iymyf45d4edovtkiqyrgwwo76a34nkwri6iaegn3fvid5xgtbrq3kmzrgajsjvz7e45kv3j5mjy2jlwzpsu4ec5zx5gvr43pcjxlhiufmfu4lntqbz433xblctrm7oyzmvhwi5amuzybwwvlp3ecm7rh3esws735zcbrn6qevdji5xc4onmro6wt4aaym5f4dsrfpqu2yd3cggns7x4zop7q7wncldsh6vg6y4sndlhwldjis2f6gx3a5megcpyipdrbbmc33c6cs4ree4vzrqtwjcjl7dfea4lzjjjfreg7ryrn73qbc44eyvxxtsb4hpuogderdc7tmjohifq2gd7kloixtssfnhjpdvalusvudjsktk7uvsix4vz47jc5zb3ta62nq5cm5to3s7gc45xllbsltte6gprqig2g2yxjedzbmr7xg3ltdqp6jx37tfb7fhe3l5krs7rar22zqlevy3cgrkwjjr23fjsudprqt2dxaxz2ujcccsdtwyy7yeqfj5fd6j7adypm6ffozs53p44gd35diwf77eryqpemz2yk3ltxnhbtezh4fx2trpat5k2vtzkvjy5yk4csbgofiar7kyf5ho3mn3vdx3svvreseke5ujai4bx73mjgovyttuw5wctwng3meyyw2rvh7dlqjeu6f6oq3y7ivfght6vhxktx7priiszhuycm2lu5ga5tahzqa4dakkyoambbubauad3s7xhypfjfxq6oaqphqej4foaw4yghaqkcc7xwnbwk62nn33b6tu2l2myre6s7s6baeaqh2a";
                var cert = new X509Certificate2(cert32.FromBase32(), config.NodeConfig.SslCertPassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                return cert;
            }).As<X509Certificate2>();
        }

        private static void RegisterPeerSettings(ContainerBuilder containerBuilder)
        {
            containerBuilder.Register(x =>
            {
                var keyStore = x.Resolve<IKeyStore>();
                var privateKey = keyStore.KeyStoreDecrypt(KeyRegistryTypes.DefaultKey);
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

                var configRoot = new ConfigurationBuilder().AddInMemoryCollection(peerConfig).Build();

                var peerSettingsObj = new PeerSettings(configRoot);
                containerBuilder.RegisterInstance(peerSettingsObj).As<IPeerSettings>();
                return peerSettingsObj;
            }).As<IPeerSettings>();
        }

        private static void RegisterRpcClientSettings(ContainerBuilder containerBuilder, string path)
        {
            containerBuilder.Register(x =>
            {
                var config = x.Resolve<Config>();
                var rpcClientSettings = new RpcClientSettings
                {
                    HostAddress = config.NodeConfig.IpAddress,
                    Port = config.NodeConfig.Port,
                    PfxFileName = Path.Combine(path, config.NodeConfig.PfxFileName),
                    SslCertPassword = config.NodeConfig.SslCertPassword,
                    PublicKey = config.NodeConfig.PublicKey
                };
                return rpcClientSettings;
            }).As<IRpcClientConfig>();
        }
    }
}