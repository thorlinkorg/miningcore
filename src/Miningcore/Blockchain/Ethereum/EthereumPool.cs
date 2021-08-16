/*
Copyright 2017 Coin Foundry (coinfoundry.org)
Authors: Oliver Weichhold (oliver@weichhold.com)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Reactive;
using System.Reactive.Linq;
using System.Reactive.Threading.Tasks;
using System.Threading;
using System.Threading.Tasks;
using Autofac;
using AutoMapper;
using Miningcore.Blockchain.Ethereum.Configuration;
using Miningcore.Configuration;
using Miningcore.Extensions;
using Miningcore.JsonRpc;
using Miningcore.Messaging;
using Miningcore.Mining;
using Miningcore.Notifications.Messages;
using Miningcore.Persistence;
using Miningcore.Persistence.Repositories;
using Miningcore.Stratum;
using Miningcore.Time;
using Miningcore.Util;
using Nethereum.Util;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Miningcore.Blockchain.Ethereum
{
    [CoinFamily(CoinFamily.Ethereum)]
    public class EthereumPool : PoolBase
    {
        public EthereumPool(IComponentContext ctx,
            JsonSerializerSettings serializerSettings,
            IConnectionFactory cf,
            IStatsRepository statsRepo,
            IMapper mapper,
            IMasterClock clock,
            IMessageBus messageBus) :
            base(ctx, serializerSettings, cf, statsRepo, mapper, clock, messageBus)
        {
        }

        private object currentJobParams;
        private EthereumJobManager manager;

        private async Task OnSubscribeAsync(StratumClient client, Timestamped<JsonRpcRequest> tsRequest)
        {
            var request = tsRequest.Value;
            var context = client.ContextAs<EthereumWorkerContext>();

            if(request.Id == null)
                throw new StratumException(StratumError.Other, "missing request id");

            var requestParams = request.ParamsAs<string[]>();

            if(requestParams == null || requestParams.Length < 2 || requestParams.Any(string.IsNullOrEmpty))
                throw new StratumException(StratumError.MinusOne, "invalid request");

            manager.PrepareExtraNonce(client);

            var data = new object[]
                {
                    new object[]
                    {
                        EthereumStratumMethods.MiningNotify,
                        client.ConnectionId,
                        EthereumConstants.EthereumStratumVersion
                    },
                    context.ExtraNonce1
                }
                .ToArray();

            await client.RespondAsync(data, request.Id);
            logger.Info(() => $"[{client.ConnectionId}] subscribe extra nonce : {context.ExtraNonce1} to worker:{context.Miner}:{context.Worker}");
            // setup worker context
            context.IsSubscribed = true;
            context.UserAgent = requestParams[0].Trim();
        }

        private async Task OnExtraNonceSubscribeAsync(StratumClient client, Timestamped<JsonRpcRequest> tsRequest)
        {
            var request = tsRequest.Value;
            var context = client.ContextAs<EthereumWorkerContext>();

            if(request.Id == null)
                throw new StratumException(StratumError.Other, "missing request id");


            await client.NotifyAsync(EthereumStratumMethods.SetExtraNonce, new object[] { context.ExtraNonce1 });
            logger.Info(() => $"[{client.ConnectionId}] set_extranonce {context.ExtraNonce1} to worker:{context.Miner}:{context.Worker}");

        }
        private async Task OnAuthorizeAsync(StratumClient client, Timestamped<JsonRpcRequest> tsRequest)
        {
            var request = tsRequest.Value;
            var context = client.ContextAs<EthereumWorkerContext>();

            if(request.Id == null)
                throw new StratumException(StratumError.MinusOne, "missing request id");

            var requestParams = request.ParamsAs<string[]>();
            var workerValue = requestParams?.Length > 0 ? requestParams[0] : null;
            logger.Info(() => $"[{client.ConnectionId}] Get Authorize Request for worker {workerValue}");
            var password = requestParams?.Length > 1 ? requestParams[1] : null;
            var passParts = password?.Split(PasswordControlVarsSeparator);

            // extract worker/miner
            var workerParts = workerValue?.Split('.');
            var minerName = workerParts?.Length > 0 ? workerParts[0].Trim() : null;
            var workerName = workerParts?.Length > 1 ? workerParts[1].Trim() : null;

            // assumes that workerName is an address
            context.IsAuthorized = !string.IsNullOrEmpty(minerName) && manager.ValidateAddress(minerName);
            context.Miner = minerName;
            context.Worker = workerName;

            // respond
            await client.RespondAsync(context.IsAuthorized, request.Id);

            // extract control vars from password
            var staticDiff = GetStaticDiffFromPassparts(passParts);
            if(staticDiff.HasValue &&
                (context.VarDiff != null && staticDiff.Value >= context.VarDiff.Config.MinDiff ||
                    context.VarDiff == null && staticDiff.Value > context.Difficulty))
            {
                context.VarDiff = null; // disable vardiff
                context.SetDifficulty(staticDiff.Value);

                logger.Info(() => $"[{client.ConnectionId}] Setting static difficulty of {staticDiff.Value}");
            }

            await EnsureInitialWorkSent(client);

            // log association
            logger.Info(() => $"[{client.ConnectionId}] Authorized worker {workerValue}");
        }

        private async Task OnSubmitAsync(StratumClient client, Timestamped<JsonRpcRequest> tsRequest, CancellationToken ct)
        {
            logger.Info(() => $"[{client.ConnectionId}] proccessing submitted share, context difficulty:{ client.ContextAs<EthereumWorkerContext>().Difficulty}");
            var request = tsRequest.Value;
            var context = client.ContextAs<EthereumWorkerContext>();

            try
            {
                if(request.Id == null)
                    throw new StratumException(StratumError.MinusOne, "missing request id");

                // check age of submission (aged submissions are usually caused by high server load)
                var requestAge = clock.Now - tsRequest.Timestamp.UtcDateTime;

                if(requestAge > maxShareAge)
                {
                    logger.Warn(() => $"[{client.ConnectionId}] Dropping stale share submission request (server overloaded?)");
                    return;
                }

                // validate worker
                if(!context.IsAuthorized)
                    throw new StratumException(StratumError.UnauthorizedWorker, "unauthorized worker");
                else if(!context.IsSubscribed)
                    throw new StratumException(StratumError.NotSubscribed, "not subscribed");

                // check request
                string[] submitRequest = request.ParamsAs<string[]>();
                string fullNonce = null;
                //var fullNonce = context.ExtraNonce1 + submitRequest[2];
                if (submitRequest[2].Length == 16)
                    fullNonce = submitRequest[2];
                else
                    fullNonce = context.ExtraNonce1 + submitRequest[2];

                string hash =  manager.getJob(submitRequest[1]).BlockTemplate.Header;
                string messageToHash = hash + fullNonce;
                
                //logger.Info(() => $"[{client.ConnectionId}] hash+fullnonce:{ messageToHash}");
               /* var messageHash = System.Security.Cryptography.SHA256.Create().ComputeHash((messageToHash).HexToByteArray());
                logger.Info(() => $"submitRequest MessageHash :0x{BitConverter.ToString(messageHash).Replace("-", "")}");*/
                var curve = ECNamedCurveTable.GetByName("prime256v1");
                var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

                //TODO Adding test signature, MUST REMOVE when real rig is connected-----------------------------
                /*
                if(submitRequest.Length == 3)
                { 
                    // Generate a test private key.
                    var privateKey = Utils.HexToByteArray("0xd0c7bc5d5565202abaf8c9b66ba1b9164d9babcfc4abebb827f25890e5183666");
                    var privateKeyParameters = new ECPrivateKeyParameters(new Org.BouncyCastle.Math.BigInteger(privateKey), domainParams);

                    //Genrate public key
                    Org.BouncyCastle.Math.BigInteger d = new Org.BouncyCastle.Math.BigInteger(privateKey);
                    ECPoint q = curve.G.Multiply(d);
                    var publicParams = new ECPublicKeyParameters(q, domainParams);
                    var publicKey = publicParams.Q.GetEncoded(false);
                    string publicKeyStr = "0x" + BitConverter.ToString(publicKey).Replace("-", "");

                    //Sign the message
                    ISigner signer = SignerUtilities.GetSigner("SHA-256withECDSA");
                    signer.Init(true, privateKeyParameters);
                    signer.BlockUpdate((messageToHash).HexToByteArray(), 0, (messageToHash).HexToByteArray().Length);
                    var signature = signer.GenerateSignature();
                    string signatureStr = "0x" + BitConverter.ToString(signature).Replace("-", "");

                    List<string> list = submitRequest.ToList();
                    list.Add(signatureStr);
                    list.Add(publicKeyStr);
                    submitRequest = list.ToArray();
                }
                */

                if(submitRequest.Length != 5 ||
                    submitRequest.Any(string.IsNullOrEmpty))
                    throw new StratumException(StratumError.MinusOne, "malformed PoW result");

                string rigSignature = submitRequest[3]; //Der signature
                //logger.Info(() => $"[{client.ConnectionId}] Signature  :{rigSignature}");
                var rigSignatureByte = rigSignature.HexToByteArray(); 

                var pubkey = submitRequest[4];//publick key start with 0x04
                //logger.Info(() => $"[{client.ConnectionId}] pubkey  :{pubkey}");

                var publickKeyHash = System.Security.Cryptography.SHA256.Create().ComputeHash(pubkey.HexToByteArray());
                var publickKeyHashStr = "0x" + BitConverter.ToString(publickKeyHash).Replace("-", "");
                logger.Info(() => $"[{client.ConnectionId}] Rig: {publickKeyHashStr}");

                var ecdp = TlsEccUtilities.GetParametersForNamedCurve(NamedCurve.secp256r1);
                var basePoint = TlsEccUtilities.ValidateECPublicKey(TlsEccUtilities.DeserializeECPublicKey(null, ecdp, pubkey.HexToByteArray()));
                SubjectPublicKeyInfo subinfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(basePoint);
                ECPublicKeyParameters bpubKey = (ECPublicKeyParameters) PublicKeyFactory.CreateKey(subinfo);

                //check signature
                var signer2 = SignerUtilities.GetSigner("SHA-256withECDSA");
                signer2.Init(false, bpubKey);
                signer2.BlockUpdate((messageToHash).HexToByteArray(), 0, (messageToHash).HexToByteArray().Length);
                var success = signer2.VerifySignature(rigSignatureByte);
                if(!success)
                {
                    throw new StratumException(StratumError.MinusOne, "invalid signature");
                }

                //check deposit 
               /* Deposit deposit = contract.GetDeposit(publickKeyHashStr);
                BigInteger fuel = contract.GetFuel();
                BigInteger height = contract.GetHeight();
                BigInteger rigNumber = contract.GetOwnerRigNumber(depositAddress);

                if(deposit.deposit < rigNumber * (BigInteger.Parse("30000000000000000000000") / BigInteger.Pow(2, (int) BigInteger.Divide(height, 140000))) + fuel * 8) 
                {
                    throw new StratumException(StratumError.MinusOne, "ODIN deposit is insufficient");
                }
                
                PledgeContract.deposits[deposit.owner] = (BigDecimal.Parse(deposit.deposit.ToString()) / BigDecimal.Parse("1000000000000000000")).ToString();//show to ui*/
                // recognize activity
                context.LastActivity = clock.Now;

                var poolEndpoint = poolConfig.Ports[client.PoolEndpoint.Port];

                var share = await manager.SubmitShareAsync(client, submitRequest, ct);

                await client.RespondAsync(true, request.Id);

                // publish
                messageBus.SendMessage(new ClientShare(client, share));

                // telemetry
                PublishTelemetry(TelemetryCategory.Share, clock.Now - tsRequest.Timestamp.UtcDateTime, true);

                logger.Info(() => $"[{client.ConnectionId}] Share accepted: D={Math.Round(share.Difficulty / EthereumConstants.Pow2x32, 3)}");
                await EnsureInitialWorkSent(client);

                // update pool stats
                if(share.IsBlockCandidate)
                    poolStats.LastPoolBlockTime = clock.Now;

                // update client stats
                context.Stats.ValidShares++;
                await UpdateVarDiffAsync(client);
            }

            catch(StratumException ex)
            {
                // telemetry
                PublishTelemetry(TelemetryCategory.Share, clock.Now - tsRequest.Timestamp.UtcDateTime, false);

                // update client stats
                context.Stats.InvalidShares++;
                logger.Info(() => $"[{client.ConnectionId}] Share rejected: {ex.Message}");

                // banning
                ConsiderBan(client, context, poolConfig.Banning);

                throw;
            }
        }

        private void changeSignatureEndian(Span<byte> outBytes, Span<byte> inBytes) {
            for(int i = 0; i< 32; i++)
            {
                outBytes[31 - i] = inBytes[i];
            }
            for(int i = 32; i< 64; i++)
            {
                outBytes[63 - i + 32] = inBytes[i];
            }
            outBytes[64] = inBytes[64];//last byte is recid, copy it
        }
        private async Task EnsureInitialWorkSent(StratumClient client)
        {
            var context = client.ContextAs<EthereumWorkerContext>();
            var sendInitialWork = false;

            lock(context)
            {
                if(context.IsSubscribed && context.IsAuthorized && !context.IsInitialWorkSent)
                {
                    context.IsInitialWorkSent = true;
                    sendInitialWork = true;
                }
            }

            if(sendInitialWork)
            {
                // send intial update
                await client.NotifyAsync(EthereumStratumMethods.SetDifficulty, new object[] { context.Difficulty });
                await client.NotifyAsync(EthereumStratumMethods.MiningNotify, currentJobParams);
                //.Info(() => $"[Send new job in EnsureInitialWorkSent] {currentJobParams}");
            }
        }

        protected virtual Task OnNewJobAsync(object jobParams)
        {
            currentJobParams = jobParams;

            logger.Info(() => $"Broadcasting job");

            var tasks = ForEachClient(async client =>
            {
                if(!client.IsAlive)
                    return;

                var context = client.ContextAs<EthereumWorkerContext>();

                if(context.IsSubscribed && context.IsAuthorized && context.IsInitialWorkSent)
                {
                    // check alive
                    var lastActivityAgo = clock.Now - context.LastActivity;

                    if(poolConfig.ClientConnectionTimeout > 0 &&
                        lastActivityAgo.TotalSeconds > poolConfig.ClientConnectionTimeout)
                    {
                        logger.Info(() => $"[{client.ConnectionId}] Booting zombie-worker (idle-timeout exceeded)");
                        DisconnectClient(client);
                        return;
                    }

                    // varDiff: if the client has a pending difficulty change, apply it now
                    if(context.ApplyPendingDifficulty())
                        await client.NotifyAsync(EthereumStratumMethods.SetDifficulty, new object[] { context.Difficulty });

                    // send job
                    await client.NotifyAsync(EthereumStratumMethods.MiningNotify, currentJobParams);

                    logger.Info(() => $"[{client.ConnectionId}] send new job to  worker:{context.Miner}:{context.Worker}");

                }
            });

            return Task.WhenAll(tasks);
        }

#region Overrides

        protected override async Task SetupJobManager(CancellationToken ct)
        {
            manager = ctx.Resolve<EthereumJobManager>();
            manager.Configure(poolConfig, clusterConfig);

            await manager.StartAsync(ct);

            if(poolConfig.EnableInternalStratum == true)
            {
                disposables.Add(manager.Jobs
                    .Select(job => Observable.FromAsync(async () =>
                    {
                        try
                        {
                            await OnNewJobAsync(job);
                        }

                        catch(Exception ex)
                        {
                            logger.Debug(() => $"{nameof(OnNewJobAsync)}: {ex.Message}");
                        }
                    }))
                    .Concat()
                    .Subscribe(_ => { }, ex =>
                    {
                        logger.Debug(ex, nameof(OnNewJobAsync));
                    }));

                // we need work before opening the gates
                await manager.Jobs.Take(1).ToTask(ct);
            }

            else
            {
                // keep updating NetworkStats
                disposables.Add(manager.Jobs.Subscribe());
            }
        }

        protected override async Task InitStatsAsync()
        {
            await base.InitStatsAsync();

            blockchainStats = manager.BlockchainStats;
        }

        protected override WorkerContextBase CreateClientContext()
        {
            return new EthereumWorkerContext();
        }

        protected override async Task OnRequestAsync(StratumClient client,
            Timestamped<JsonRpcRequest> tsRequest, CancellationToken ct)
        {
            var request = tsRequest.Value;

            try
            {
                switch(request.Method)
                {
                    case EthereumStratumMethods.Subscribe:
                        await OnSubscribeAsync(client, tsRequest);
                        break;

                    case EthereumStratumMethods.Authorize:
                        await OnAuthorizeAsync(client, tsRequest);
                        break;

                    case EthereumStratumMethods.SubmitShare:
                        await OnSubmitAsync(client, tsRequest, ct);
                        break;

                    case EthereumStratumMethods.ExtraNonceSubscribe:
                        await OnExtraNonceSubscribeAsync(client, tsRequest);
                        //await client.RespondErrorAsync(StratumError.Other, "not supported", request.Id, false);
                        break;

                    default:
                        logger.Debug(() => $"[{client.ConnectionId}] Unsupported RPC request: {JsonConvert.SerializeObject(request, serializerSettings)}");

                        await client.RespondErrorAsync(StratumError.Other, $"Unsupported request {request.Method}", request.Id);
                        break;
                }
            }

            catch(StratumException ex)
            {
                await client.RespondErrorAsync(ex.Code, ex.Message, request.Id, false);
            }
        }

        public override double HashrateFromShares(double shares, double interval)
        {
            var result = shares / interval;
            return result;
        }

        protected override async Task OnVarDiffUpdateAsync(StratumClient client, double newDiff)
        {
            await base.OnVarDiffUpdateAsync(client, newDiff);

            // apply immediately and notify client
            var context = client.ContextAs<EthereumWorkerContext>();

            if(context.HasPendingDifficulty)
            {
                context.ApplyPendingDifficulty();

                // send job
                await client.NotifyAsync(EthereumStratumMethods.SetDifficulty, new object[] { context.Difficulty });
                await client.NotifyAsync(EthereumStratumMethods.MiningNotify, currentJobParams);
                //logger.Info(() => $"[Send new job in OnVarDiffUpdateAsync] {currentJobParams}");
                manager.PrepareExtraNonce(client);
                await client.NotifyAsync(EthereumStratumMethods.SetExtraNonce, new object[] { context.ExtraNonce1 });
                logger.Info(() => $"[{client.ConnectionId}] set_extranonce to worker: {context.ExtraNonce1}");
            }
        }

        public override void Configure(PoolConfig poolConfig, ClusterConfig clusterConfig)
        {
            base.Configure(poolConfig, clusterConfig);

            // validate mandatory extra config
            var extraConfig = poolConfig.PaymentProcessing?.Extra?.SafeExtensionDataAs<EthereumPoolPaymentProcessingConfigExtra>();
            if(clusterConfig.PaymentProcessing?.Enabled == true && extraConfig?.CoinbasePassword == null)
                logger.ThrowLogPoolStartupException("\"paymentProcessing.coinbasePassword\" pool-configuration property missing or empty (required for unlocking wallet during payment processing)");
        }

#endregion // Overrides
    }
    public static class Utils
    {
        public static byte[] HexToByteArray(this string str)
        {
            if(str.StartsWith("0x"))
                str = str.Substring(2);

            var arr = new byte[str.Length >> 1];
            var count = str.Length >> 1;

            for(var i = 0; i < count; ++i)
                arr[i] = (byte) ((GetHexVal(str[i << 1]) << 4) + GetHexVal(str[(i << 1) + 1]));

            return arr;
        }

        private static int GetHexVal(char hex)
        {
            var val = (int) hex;
            return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
        }
    }
}
