﻿using System;
using Catalyst.Core.Lib.Extensions;
using Catalyst.Core.Lib.Extensions.Protocol.Wire;
using Catalyst.Core.Modules.Cryptography.BulletProofs;
using Catalyst.Protocol.Cryptography;
using Catalyst.Protocol.Network;
using Catalyst.Protocol.Rpc.Node;
using Catalyst.Protocol.Transaction;
using Catalyst.Protocol.Wire;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Nethermind.Dirichlet.Numerics;

namespace DocumentStamp.Helper
{
    public static class StampTransactionHelper
    {
        private static readonly SigningContext DevNetPublicTransactionContext = new SigningContext
        {
            NetworkType = NetworkType.Devnet,
            SignatureType = SignatureType.TransactionPublic
        };

        public static BroadcastRawTransactionRequest GenerateStampTransaction(byte[] data, uint amount, int fee,
            int nonce = 0)
        {
            var cryptoWrapper = new FfiWrapper();
            var privateKey = cryptoWrapper.GeneratePrivateKey();
            var publicKey = ByteString.CopyFrom(privateKey.GetPublicKey().Bytes);

            var transaction = new TransactionBroadcast
            {
                PublicEntries =
                {
                    new PublicEntry
                    {
                        Amount = ((UInt256) amount).ToUint256ByteString(),
                        Base = new BaseEntry
                        {
                            Nonce = (ulong) nonce,
                            SenderPublicKey = privateKey.GetPublicKey().Bytes.ToByteString(),
                            ReceiverPublicKey = publicKey,
                            TransactionFees = ((UInt256) fee).ToUint256ByteString()
                        }
                    }
                },
                ContractEntries =
                {
                    new ContractEntry
                    {
                        Amount = ((UInt256) amount).ToUint256ByteString(),
                        Base = new BaseEntry
                        {
                            Nonce = (ulong) nonce,
                            SenderPublicKey = privateKey.GetPublicKey().Bytes.ToByteString(),
                            ReceiverPublicKey = publicKey,
                            TransactionFees = ((UInt256) fee).ToUint256ByteString()
                        },
                        Data = data.ToByteString()
                    }
                },
                Timestamp = Timestamp.FromDateTime(DateTime.UtcNow)
            };

            var signedTransaction = transaction.Sign(cryptoWrapper, privateKey, DevNetPublicTransactionContext);
            var broadcastRawTransactionRequest = new BroadcastRawTransactionRequest
            {
                Transaction = signedTransaction
            };

            return broadcastRawTransactionRequest;
        }
    }
}