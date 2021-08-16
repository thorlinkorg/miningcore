using Nethereum;
using Nethereum.Hex.HexTypes;
using Nethereum.Web3;
using Nethereum.Contracts;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Utilities;
using System.Numerics;
using Miningcore.Configuration;
using System.Threading;
using System.Globalization;

namespace Miningcore.Blockchain.Ethereum
{
    class Deposit
    {
        public string owner { get; set; }
        public BigInteger deposit { get; set; }
    }

    class PledgeContract
    {
        private readonly string url;
        private readonly string contractAddress;
        private const string ABI = @"[{'inputs': [{'internalType': 'bytes32','name': 'rig','type': 'bytes32'},{'internalType': 'uint256','name': 'height','type': 'uint256'}],'name': 'isRigEligible','outputs': [{'internalType': 'bool','name': '','type': 'bool'}],'stateMutability': 'view','type': 'function'},{'inputs':[{'internalType':'address','name':'user','type':'address'}],'name':'getOwnerRigNumber','outputs':[{'internalType':'uint256','name':'','type':'uint256'}],'stateMutability':'view','type':'function'},{'inputs': [],'name': '_thorHeight','outputs': [{'internalType': 'uint256',	'name': '','type': 'uint256'}],	'stateMutability': 'view','type': 'function'},{'inputs':[{'internalType':'address','name':'','type':'address'}],'name':'depositPowers','outputs':[{'internalType':'uint256','name':'','type':'uint256'}],'stateMutability':'view','type':'function'},{'inputs': [],'name': '_fuel','outputs': [{'internalType': 'uint256','name': '','type': 'uint256'}],'stateMutability': 'view','type': 'function'},{'inputs':[{'internalType':'address','name':'','type':'address'}],'name':'ownerDeposits','outputs':[{'internalType':'uint256','name':'','type':'uint256'}],'stateMutability':'view','type':'function'},{'inputs':[{'internalType':'bytes32','name':'','type':'bytes32'}],'name':'rigOwners','outputs':[{'internalType':'address','name':'','type':'address'}],'stateMutability':'view','type':'function'}]";
        Web3 web3;
        Contract contract;
        Function funRigOwners;
        Function funOwnerDeposits;
        Function funGetFuel;
        Function funGetHeight;
        Function funGetOwnerRigNumber;
        Function funGetDepositPower;
        Function funcIsRigEligible;
        public static Dictionary<string, string> deposits = new Dictionary<string, string>();
        public static Dictionary<string, DateTime> bindRigInvaidTimes = new Dictionary<string, DateTime>();
        public static Dictionary<string, DateTime> unBindRigInvalidTimes = new Dictionary<string, DateTime>();
        public static Dictionary<string, bool> isRigEligibleCache = new Dictionary<string, bool>();
        public PledgeContract(OdinEndpointConfig config)
        {
            url = config.Host + ":" + config.Port;
            if(config.ContractAddress.ToLower().StartsWith("odx"))
            {
                contractAddress = "0x" + config.ContractAddress.Substring(3);
            }
            else if(config.ContractAddress.ToLower().StartsWith("0x"))
            {
                contractAddress = config.ContractAddress;
            }
            else
            {
                contractAddress = "0x" + config.ContractAddress;
                Console.WriteLine("contract address might be typo:" + config.ContractAddress);
            }
            Init();
        }
        private bool Init()
        {
            Console.WriteLine("Init web3");
            web3 = new Web3(url);
            //web3CreatedTime = DateTime.Now;
            contract = web3.Eth.GetContract(ABI, contractAddress);
            funRigOwners = contract.GetFunction("rigOwners");
            funOwnerDeposits = contract.GetFunction("ownerDeposits");
            funGetFuel = contract.GetFunction("_fuel");
            funGetHeight = contract.GetFunction("_thorHeight");
            funGetOwnerRigNumber = contract.GetFunction("getOwnerRigNumber");
            funGetDepositPower = contract.GetFunction("depositPowers");
            funcIsRigEligible = contract.GetFunction("isRigEligible");
            return true;
        }

        private void Close()
        {
            web3 = null;
        }

        public bool IsRigBind(string rig, string owner)
        {

            if (bindRigInvaidTimes.ContainsKey(rig))
            {
                if (DateTime.Now < bindRigInvaidTimes[rig])
                {
                    return true;
                }
                else
                {
                    bindRigInvaidTimes.Remove(rig);
                }
            }

            if(unBindRigInvalidTimes.ContainsKey(rig))
            {
                if(DateTime.Now < unBindRigInvalidTimes[rig])
                {
                    return false;
                }
                else
                {
                    unBindRigInvalidTimes.Remove(rig);
                }
            }

            Task<string> returnOwner = funRigOwners.CallAsync<string>(rig.HexToByteArray());
            if(string.Compare(returnOwner.Result, owner, true) == 0)
            {
                Random random = new Random(Int32.Parse(rig.Substring(60), NumberStyles.AllowHexSpecifier));
                int time = 3600 * 6 + random.Next(2600);
                bindRigInvaidTimes.Add(rig, DateTime.Now + TimeSpan.FromSeconds(time));
                return true;
            }
            else
            {
                Random random = new Random(Int32.Parse(rig.Substring(60), NumberStyles.AllowHexSpecifier));
                int time = 3600 * 2 + random.Next(900);
                unBindRigInvalidTimes.Add(rig, DateTime.Now + TimeSpan.FromSeconds(time));
                return false;
            }
        }

        public Deposit GetDeposit(string rig)
        {
/*            if(DateTime.Now.Subtract(web3CreatedTime) > new TimeSpan(0, 1, 0))
            {
                Close();
                Init();
            }*/
            Task<string> returnOwner = funRigOwners.CallAsync<string>(rig.HexToByteArray());
            string owner = returnOwner.Result;
            if(string.Compare(owner, EthereumConstants.OdinAddress0, true) == 0)
            {
                Deposit d = new Deposit
                {
                    deposit = BigInteger.Zero,
                    owner = owner
                };
                return d;
            }
            else
            {
                Task<BigInteger> returnDeposit = funOwnerDeposits.CallAsync<BigInteger>(owner);
                Deposit d = new Deposit
                {
                    deposit = returnDeposit.Result,
                    owner = owner
                };
                return d;

            }
        }

        public bool isRigEligible(string rig, BigInteger height)
        {
            if(isRigEligibleCache.ContainsKey(rig))
            {
                return isRigEligibleCache[rig];
            }
                
            Task<bool> returnResult = funcIsRigEligible.CallAsync<bool>(rig.HexToByteArray(), height);
            bool isEligible = returnResult.Result;
            isRigEligibleCache.Add(rig, isEligible);
            return isEligible;

        }

        public bool isRigEligibleDirect(string rig, BigInteger height)
        {

            Task<bool> returnResult = funcIsRigEligible.CallAsync<bool>(rig.HexToByteArray(), height);
            bool isEligible = returnResult.Result;
            return isEligible;

        }

        public void clearRigEligibleCache()
        {
            isRigEligibleCache.Clear();
        }

        public BigInteger GetFuel()
        {
/*            if(DateTime.Now.Subtract(web3CreatedTime) > new TimeSpan(0, 1, 0))
            {
                Close();
                Init();
            }*/
            Task<BigInteger> returnFuel = funGetFuel.CallAsync<BigInteger>();
            return returnFuel.Result;
            
        }

        public BigInteger GetHeight()
        {
/*            if(DateTime.Now.Subtract(web3CreatedTime) > new TimeSpan(0, 1, 0))
            {
                Close();
                Init();
            }*/
            Task<BigInteger> returnHeight = funGetHeight.CallAsync<BigInteger>();
            return returnHeight.Result;

        }

        public BigInteger GetDepositPower(string address)
        {
/*            if(DateTime.Now.Subtract(web3CreatedTime) > new TimeSpan(0, 1, 0))
            {
                Close();
                Init();
            }*/
            Task<BigInteger> returnPower = funGetDepositPower.CallAsync<BigInteger>(address);
            return returnPower.Result;

        }

        public BigInteger GetOwnerRigNumber(string user)
        {
/*            if(DateTime.Now.Subtract(web3CreatedTime) > new TimeSpan(0, 1, 0))
            {
                Close();
                Init();
            }*/
            Task<BigInteger> returnNumber = funGetOwnerRigNumber.CallAsync<BigInteger>(user);
            return returnNumber.Result;

        }
    }
}
