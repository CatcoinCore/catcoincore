// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <hash.h> // for signet block challenge hash
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "NY Times - December 23, 2013 - For Today's Babes, Toyland Is Digital";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 16; // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L1885 
        consensus.BIP34Height = 111; // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L1874 
        consensus.BIP34Hash = uint256S("0xfa09d204a83a768ed5a7c8d441fa62f2043abf420cff1226c7b4329aeb9d51cf");
        consensus.BIP65Height = INT_MAX; // bab3041e8977e0dc3eeff63fe707b92bde1dd449d8efafb248c27c8264cc311a
        consensus.BIP66Height = INT_MAX; // 7aceee012833fa8952f8835d8b1b3ae233cd6ab08fdb27a771d2bd7bdc491894
        consensus.CSVHeight = INT_MAX; // 53e0af7626f7f51ce9f3b6cfc36508a5b1d2f6c4a75ac215dc079442692a4c0b
        consensus.SegwitHeight = INT_MAX; // 0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893
        consensus.CIP01Height = 20289;
        consensus.CIP02Height = 21346;
        consensus.CIP03Height = 27260;
        consensus.CIP04Height = 46331;
        consensus.CIP05Height = 390925;
        consensus.MinBIP9WarningHeight = 4600000; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespanV1 = 14 * 24 * 60 * 60;
        consensus.nPowTargetTimespanV2 = 6 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.nLwmaAveragingWindow = 45;
        consensus.nPowTargetSpacingMax = 12 * consensus.nPowTargetSpacing;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 7500; // 75% of 10000
        consensus.nMinerConfirmationWindow = 10000;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartHeight = 400000;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeoutHeight = 450000;

        // Deployment of MWEB (LIP-0002, LIP-0003, and LIP-0004)
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nStartHeight = 4510000;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nTimeoutHeight = 4600000;

        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000004853b14a65c5bb6c"); // getblockchaininfo chainwork field @ Block 369630
        consensus.defaultAssumeValid = uint256S("0x09446a44415b5c411795b963e1db3558b571eaa82b961f27d9645c99999c0d38"); // Block 369630

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfc; // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L3325
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xb7;
        pchMessageStart[3] = 0xdc;
        nDefaultPort = 9933; // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/protocol.h#L21
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlock(1387838302, 588050, 0x1e0ffff0, 1, 50 * COIN); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L3022
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xbc3b4ec43c4ebb2fef49e6240812549e61ffa623d9418608aa90eaad26c96296")); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L35C27-L35C93
        assert(genesis.hashMerkleRoot == uint256S("0x4007a33db5d9cdf2aab117335eb8431c8d13fb86e0214031fdaebe69a0f29cf7"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.

        // All of these require a new core-node on release
        vSeeds.emplace_back("catcoin.seeds.multicoin.co"); // Run by ahmedbodi of multicoin.co Pool
        vSeeds.emplace_back("catalyst.ovh"); // its_only_mathijs
        vSeeds.emplace_back("dnsseed.catcointomars.top"); // Skinlin
        vSeeds.emplace_back("dnsseed.wildcat.ovh"); // CMinor
        vSeeds.emplace_back("dnsseed.ogcatcoin.org"); // TheCrippledStreamer, Currently Broken
        vSeeds.emplace_back("dnsseed.catcoin.ovh"); // Navin
        vSeeds.emplace_back("dnsseed.bcats.top"); // staygoldcrypto.com
        vSeeds.emplace_back("dnsseed.jjcatcoin.top"); // JJ - 2mars.biz and JJ-Com Tech
        vSeeds.emplace_back("dnsseed.catsonmylap.top"); // def [etica-stats.org]
        vSeeds.emplace_back("dnsseed.kr105.com"); // kr105
        vSeeds.emplace_back("dnsseed.remembermeasyoupassby.top"); // lambourghini_eth

        // Legacy Wallet
        vSeeds.emplace_back("seed.catcoinwallets.com"); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L3325
        vSeeds.emplace_back("cat.geekhash.org"); // GeekHash Pool
        

        // https://github.com/CatcoinOfficial/CatcoinRelease/blob/master/src/base58.h#L275C30-L275C89
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,21); // Catcoin addresses start with 9, because cats has 9 lives
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,88); // This is used, its used to generate the prefix for private keys
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,149); // This is the WIF Prefix used by Trezor's ETC - PUBKEY_ADDRESS + 128
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E}; // Currently unused
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4}; // Currently unused

        bech32_hrp = "cat"; // Unused atm
        mweb_hrp = "catmweb"; // Unused atm

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_main), std::end(chainparams_seed_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L3325
        checkpointData = {
            {
                {    4, uint256S("0xfe508d41b7dc2c3079e827d4230e6f7ddebca43c9afc721c1e6431f78d6ff1de")},
		        {	 5, uint256S("0x7fc79021dbfa30255ade9bb8d898640516d9c771c3342a9b889ce380c52c6c1f")},
		        { 5000, uint256S("0xec268a9cfe87adb4d10a147a544493406c80e00a3e6868641e520b184e7ddce3")},
		        {10000, uint256S("0x29c63023c3b8a36b59837734a9c16133a4ef08d9a0e95f639a830c56e415070d")},
		        {20000, uint256S("0x3a0c072b76a298dabffc4f825a084c0f86dc55fe58f9bf31cc7e21bbfb2ead52")},
		        {22500, uint256S("0xfd3c87eae2e9be72499978155844598a8675eff7a61c90f9aebcedc94e1b217f")},
		        {22544, uint256S("0x6dd1a90cc56cf4a46c8c47528c4861c255e86d5f97fcee53ce356174e15c3045")},
		        {22554, uint256S("0xb13e8b128989f9a9fc1a4c1e547330d0b34d3f60189c00391a116922fa4fcb8c")},
		        {22600, uint256S("0x9e2d7f2fdab36c3e2b6f0455470cd957c12172ad7877f7c8e414fd736469c8d2")},
		        {22650, uint256S("0x7afbd354496346819b8a214693af70e1431bfadbf68d49a688ae27539fc6b37e")},
		        {22700, uint256S("0x35154b803fa5700b69f8081aa6d7c798c1e7fd027971252598a18549092a1291")},
		        {22750, uint256S("0x67e6eca7d46c1a612b7638e7a503e6dbc7cca4da493f4267833a6f1c9a655a35")},
		        {22800, uint256S("0x49e84c3b5c261966c37c101ac7691886bd641a382f514c2221735088b1b2beea")},
		        {22850, uint256S("0xc44cec57381a97c3983df0ef1fcf150669dd1794943202d89b805f423a65516f")},
		        {22900, uint256S("0x44de4c262de678a23554dd06a6f57270815ea9d145f6c542ab2a8dfbd2ca242c")},
		        {22950, uint256S("0xcecc4ab30b39fc09bf85eb191e64c1660ab2206c5f80953694997ec5c2db5338")},
		        {25890, uint256S("0x4806f91100ae83904aa0113cc3acda8fe6ac422186243719a68b76c98e7487c2")},
		        {26000, uint256S("0x048d01fd25385b61d3c20f99cec5f8c0678d6ad8b5ea3160603184ad11216bfc")},
		        {30000, uint256S("0xff05303dc58caf2d102c85a0504ed16939c7840c91f5f0b37a5bf128e9afb73f")},
		        {35000, uint256S("0x8c5b56e660e47b398395fd01fd721b115fe523da400d23c82120c6fd37636423")},
		        {40000, uint256S("0xb8a6e8aaf4f92d4b521bd022de3008884eba51ff2a5c79e0269d65a03d109283")},
		        {41000, uint256S("0x88f114a60cb0841735df03cecc3c5662ffbdac184c7344d30cef4f98f5b61ed3")},
		        {42000, uint256S("0x4a538c3557ab865d74327e38837b5aac63aaebdc4718c2ee7b8101bcdd241eb6")},
		        {43000, uint256S("0xd2428f19de225b56853090fd548d1d7dd2d3d180b989c785eddb615e60f94209")},
		        {44000, uint256S("0x587b814e0a113eaf52b94e4920362f4c076d7dc942a4f8c5c4900f2d94adbc26")},
		        {44225, uint256S("0x324baa0cc239091a60c61af8a332584c02f7c7a11bc07286a4cd6c136310968d")},
		        {44227, uint256S("0xf8e16629c65f9746deed08631d3e223a9a1d88947c6b41c2107e04b35782726d")},
		        {44500, uint256S("0x0bc1f9a00a53d9bc88999b2596377bf135ab1f293b886d32a06628abbd2e4d14")},
		        {45000, uint256S("0x47f0d282919bfd3d9901ac8bf38bb41947517e2c7f80ad6ec8f9a8f09243b7dd")},
		        {45500, uint256S("0xec9ba2336ab78ad947ccdd2cbe2308a112aabf5379f0cd04cbd224d6e3845714")},
		        {46000, uint256S("0x2a6410328fdb9800565c49c0eda849e69dc5a414adab2ff73d0aec9dbf0e2458")},
		        {46500, uint256S("0x96cc990f69f8005d31e09f55455ab28b5a09c70bb89b8c6080b48a3bcc1a9342")},
		        {47000, uint256S("0x197bd9b1a38262ea8693fd1c0d68e9fdd3cc3cec713d4de0b53fcb4ff70d11fd")},
		        {47500, uint256S("0xb5618edac7edf58e50409c50802be5e3b99a582f369438d53b7d55e9b334b1b4")},
		        {48000, uint256S("0xc183240a079a0f05a1ecf9049b6805e9044f9a46d08387208f598600015b8a5e")},
		        {48500, uint256S("0x0f86070e2a86a4a9480b0adfcc27cfe05dad7e1feb08f98d997b5f9b26351a66")},
		        {50000, uint256S("0x21803a5005a2637590ecfc401193487bd09b41395c20c31ed27e4f6916295c87")},
		        {75000, uint256S("0x5607029768611e1e29294cd5987845497c2c681ee2917311ec8cf3b65e61e1c8")},
		        {100000,uint256S("0x956ca160d703130bce1422ce407eac53064565bfd357fc8ac73e1a7dda9d5764")},
		        {116828,uint256S("0x750e549a03bcc7f582c7857c162cde7cfbeb6de91cccaf794cbe6337518d6c4c")},
                {390841,uint256S("0x28323c186e997b981ce1046145af0b63dd25839b9024afe04e5e711fd61e3d84")},
            }
        };

        // https://github.com/CatcoinOfficial/CatcoinRelease/blob/master/src/checkpoints.cpp#L83
        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 28323c186e997b981ce1046145af0b63dd25839b9024afe04e5e711fd61e3d84
            /* nTime    */ 1744234908,
            /* nTxCount */ 571874,
            /* dTxRate  */ 0.000943014641769317,
        };
    }
};

/**
 * Testnet (v1)
 */
class CTestNet1Params : public CChainParams {
public:
    CTestNet1Params() {
        strNetworkID = CBaseChainParams::TESTNET1;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 16;
        consensus.BIP34Height = 16;
        consensus.BIP34Hash = uint256S("0x0");
        consensus.BIP65Height = INT_MAX;
        consensus.BIP66Height = INT_MAX;
        consensus.CSVHeight = INT_MAX;
        consensus.SegwitHeight = INT_MAX;
        consensus.CIP01Height = 1;
        consensus.CIP02Height = 50;
        consensus.CIP03Height = 100;
        consensus.CIP04Height = 150;
        consensus.CIP05Height = 1000;
        consensus.MinBIP9WarningHeight = 46000; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespanV1 = 14 * 24 * 60 * 60;
        consensus.nPowTargetTimespanV2 = 6 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.nPowTargetSpacingMax = 12 * consensus.nPowTargetSpacing;
        consensus.nLwmaAveragingWindow = 144;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 7500; // 75% of 10000
        consensus.nMinerConfirmationWindow = 10000;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartHeight = 400000;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeoutHeight = 450000;

        // Deployment of MWEB (LIP-0002, LIP-0003, and LIP-0004)
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nStartHeight = 4510000;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nTimeoutHeight = 4600000;

        consensus.nMinimumChainWork = uint256S("0x0");
        consensus.defaultAssumeValid = uint256S("0x0");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xcd;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xdf;
        nDefaultPort = 19933;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock(1387838303, 608937, 0x1e0ffff0, 1, 50 * COIN); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L3022
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xec7987a2ab5225246c5cf9b8d93b4b75bcef383a4a65d5a265bc09ed54006188")); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L35C27-L35C93
        assert(genesis.hashMerkleRoot == uint256S("0x4007a33db5d9cdf2aab117335eb8431c8d13fb86e0214031fdaebe69a0f29cf7"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("seed.catcoinwallets.com"); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L3325
        vSeeds.emplace_back("cat.geekhash.org");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,23);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,83);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,151);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x05, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x05, 0x35, 0x83, 0x94};

        bech32_hrp = "t1cat";
        mweb_hrp = "t1mweb";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 36d8ad003bac090cf7bf4e24fbe1d319554c8933b9314188d6096ac12648764d
            /* nTime    */ 0,
            /* nTxCount */ 0,
            /* dTxRate  */ 0,
        };
    }
};

/**
 * Testnet (v2)
 */
class CTestNet2Params : public CChainParams {
public:
    CTestNet2Params() {
        strNetworkID = CBaseChainParams::TESTNET2;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 16;
        consensus.BIP34Height = 16;
        consensus.BIP34Hash = uint256S("0x0");
        consensus.BIP65Height = INT_MAX;
        consensus.BIP66Height = INT_MAX;
        consensus.CSVHeight = INT_MAX;
        consensus.SegwitHeight = INT_MAX;
        consensus.CIP01Height = 1;
        consensus.CIP02Height = 50;
        consensus.CIP03Height = 100;
        consensus.CIP04Height = 150;
        consensus.CIP05Height = 1000;
        consensus.MinBIP9WarningHeight = 46000; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespanV1 = 14 * 24 * 60 * 60;
        consensus.nPowTargetTimespanV2 = 6 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.nPowTargetSpacingMax = 12 * consensus.nPowTargetSpacing;
        consensus.nLwmaAveragingWindow = 144;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 7500; // 75% of 10000
        consensus.nMinerConfirmationWindow = 10000;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartHeight = 400000;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeoutHeight = 450000;

        // Deployment of MWEB (LIP-0002, LIP-0003, and LIP-0004)
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nStartHeight = 4510000;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nTimeoutHeight = 4600000;

        consensus.nMinimumChainWork = uint256S("0x0");
        consensus.defaultAssumeValid = uint256S("0x0");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xce;
        pchMessageStart[2] = 0xc1;
        pchMessageStart[3] = 0xd0;
        nDefaultPort = 18933;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock(1387838303, 608937, 0x1e0ffff0, 1, 50 * COIN); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L3022
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xec7987a2ab5225246c5cf9b8d93b4b75bcef383a4a65d5a265bc09ed54006188")); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L35C27-L35C93
        assert(genesis.hashMerkleRoot == uint256S("0x4007a33db5d9cdf2aab117335eb8431c8d13fb86e0214031fdaebe69a0f29cf7"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("seed.catcoinwallets.com"); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L3325
        vSeeds.emplace_back("cat.geekhash.org");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,22);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,82);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,150);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x06, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x06, 0x35, 0x83, 0x94};

        bech32_hrp = "t2cat";
        mweb_hrp = "t2mweb";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 36d8ad003bac090cf7bf4e24fbe1d319554c8933b9314188d6096ac12648764d
            /* nTime    */ 0,
            /* nTxCount */ 0,
            /* dTxRate  */ 0,
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNet3Params : public CChainParams {
public:
    CTestNet3Params() {
        strNetworkID = CBaseChainParams::TESTNET3;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 16;
        consensus.BIP34Height = 16;
        consensus.BIP34Hash = uint256S("0x0");
        consensus.BIP65Height = INT_MAX;
        consensus.BIP66Height = INT_MAX;
        consensus.CSVHeight = INT_MAX;
        consensus.SegwitHeight = INT_MAX;
        consensus.CIP01Height = 1;
        consensus.CIP02Height = 50;
        consensus.CIP03Height = 100;
        consensus.CIP04Height = 150;
        consensus.CIP05Height = 1000;
        consensus.MinBIP9WarningHeight = 46000; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespanV1 = 14 * 24 * 60 * 60;
        consensus.nPowTargetTimespanV2 = 6 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.nPowTargetSpacingMax = 12 * consensus.nPowTargetSpacing;
        consensus.nLwmaAveragingWindow = 144;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 7500; // 75% of 10000
        consensus.nMinerConfirmationWindow = 10000;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartHeight = 400000;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeoutHeight = 450000;

        // Deployment of MWEB (LIP-0002, LIP-0003, and LIP-0004)
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nStartHeight = 4510000;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nTimeoutHeight = 4600000;

        consensus.nMinimumChainWork = uint256S("0x0");
        consensus.defaultAssumeValid = uint256S("0x0");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xcf;
        pchMessageStart[2] = 0xc2;
        pchMessageStart[3] = 0xd1;
        nDefaultPort = 17933;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock(1387838303, 608937, 0x1e0ffff0, 1, 50 * COIN); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L3022
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xec7987a2ab5225246c5cf9b8d93b4b75bcef383a4a65d5a265bc09ed54006188")); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L35C27-L35C93
        assert(genesis.hashMerkleRoot == uint256S("0x4007a33db5d9cdf2aab117335eb8431c8d13fb86e0214031fdaebe69a0f29cf7"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("seed.catcoinwallets.com"); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L3325
        vSeeds.emplace_back("cat.geekhash.org");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,21);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,81);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,149);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x07, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x07, 0x35, 0x83, 0x94};

        bech32_hrp = "t3cat";
        mweb_hrp = "t3mweb";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 36d8ad003bac090cf7bf4e24fbe1d319554c8933b9314188d6096ac12648764d
            /* nTime    */ 0,
            /* nTxCount */ 0,
            /* dTxRate  */ 0,
        };
    }
};

/**
 * Testnet (v4)
 */
class CTestNet4Params : public CChainParams {
public:
    CTestNet4Params() {
        strNetworkID = CBaseChainParams::TESTNET4;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 16;
        consensus.BIP34Height = 16;
        consensus.BIP34Hash = uint256S("0x0");
        consensus.BIP65Height = INT_MAX;
        consensus.BIP66Height = INT_MAX;
        consensus.CSVHeight = INT_MAX;
        consensus.SegwitHeight = INT_MAX;
        consensus.CIP01Height = 1;
        consensus.CIP02Height = 50;
        consensus.CIP03Height = 100;
        consensus.CIP04Height = 150;
        consensus.CIP05Height = 1000;
        consensus.MinBIP9WarningHeight = 46000; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespanV1 = 14 * 24 * 60 * 60;
        consensus.nPowTargetTimespanV2 = 6 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.nPowTargetSpacingMax = 12 * consensus.nPowTargetSpacing;
        consensus.nLwmaAveragingWindow = 144;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 7500; // 75% of 10000
        consensus.nMinerConfirmationWindow = 10000;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartHeight = 400000;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeoutHeight = 450000;

        // Deployment of MWEB (LIP-0002, LIP-0003, and LIP-0004)
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nStartHeight = 4510000;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nTimeoutHeight = 4600000;

        consensus.nMinimumChainWork = uint256S("0x0");
        consensus.defaultAssumeValid = uint256S("0x0");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xc3;
        pchMessageStart[3] = 0xd2;
        nDefaultPort = 16933;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock(1387838303, 608937, 0x1e0ffff0, 1, 50 * COIN); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L3022
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xec7987a2ab5225246c5cf9b8d93b4b75bcef383a4a65d5a265bc09ed54006188")); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L35C27-L35C93
        assert(genesis.hashMerkleRoot == uint256S("0x4007a33db5d9cdf2aab117335eb8431c8d13fb86e0214031fdaebe69a0f29cf7"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("seed.catcoinwallets.com"); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L3325
        vSeeds.emplace_back("cat.geekhash.org");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,20);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,80);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,148);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x08, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x08, 0x35, 0x83, 0x94};

        bech32_hrp = "t4cat";
        mweb_hrp = "t4mweb";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 36d8ad003bac090cf7bf4e24fbe1d319554c8933b9314188d6096ac12648764d
            /* nTime    */ 0,
            /* nTxCount */ 0,
            /* dTxRate  */ 0,
        };
    }
};

/**
 * Testnet (v5)
 */
class CTestNet5Params : public CChainParams {
public:
    CTestNet5Params() {
        strNetworkID = CBaseChainParams::TESTNET5;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 16;
        consensus.BIP34Height = 16;
        consensus.BIP34Hash = uint256S("0x0");
        consensus.BIP65Height = INT_MAX;
        consensus.BIP66Height = INT_MAX;
        consensus.CSVHeight = INT_MAX;
        consensus.SegwitHeight = INT_MAX;
        consensus.CIP01Height = 1;
        consensus.CIP02Height = 50;
        consensus.CIP03Height = 100;
        consensus.CIP04Height = 150;
        consensus.CIP05Height = 1000;
        consensus.MinBIP9WarningHeight = 46000; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespanV1 = 14 * 24 * 60 * 60;
        consensus.nPowTargetTimespanV2 = 6 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.nPowTargetSpacingMax = 12 * consensus.nPowTargetSpacing;
        consensus.nLwmaAveragingWindow = 144;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 7500; // 75% of 10000
        consensus.nMinerConfirmationWindow = 10000;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartHeight = 400000;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeoutHeight = 450000;

        // Deployment of MWEB (LIP-0002, LIP-0003, and LIP-0004)
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nStartHeight = 4510000;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nTimeoutHeight = 4600000;

        consensus.nMinimumChainWork = uint256S("0x0");
        consensus.defaultAssumeValid = uint256S("0x0");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xc4;
        pchMessageStart[3] = 0xd3;
        nDefaultPort = 15933;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock(1387838303, 608937, 0x1e0ffff0, 1, 50 * COIN); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L3022
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xec7987a2ab5225246c5cf9b8d93b4b75bcef383a4a65d5a265bc09ed54006188")); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L35C27-L35C93
        assert(genesis.hashMerkleRoot == uint256S("0x4007a33db5d9cdf2aab117335eb8431c8d13fb86e0214031fdaebe69a0f29cf7"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("seed.catcoinwallets.com"); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/main.cpp#L3325
        vSeeds.emplace_back("cat.geekhash.org");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,19);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,79);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,147);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x09, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x09, 0x35, 0x83, 0x94};

        bech32_hrp = "t5cat";
        mweb_hrp = "t5mweb";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 36d8ad003bac090cf7bf4e24fbe1d319554c8933b9314188d6096ac12648764d
            /* nTime    */ 0,
            /* nTxCount */ 0,
            /* dTxRate  */ 0,
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID =  CBaseChainParams::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 500; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in functional tests)
        consensus.CSVHeight = 432; // CSV activated on regtest (Used in rpc activation tests)
        consensus.SegwitHeight = 0; // SEGWIT is always activated on regtest unless overridden
        consensus.CIP01Height = 0;
        consensus.CIP02Height = 0;
        consensus.CIP03Height = 0;
        consensus.CIP04Height = 0;
        consensus.CIP05Height = 0;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespanV1 = 14 * 24 * 60 * 60;
        consensus.nPowTargetTimespanV2 = 6 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.nPowTargetSpacingMax = 12 * consensus.nPowTargetSpacing;
        consensus.nLwmaAveragingWindow = 45;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of MWEB (LIP-0002 and LIP-0003)
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nStartTime = 1601450001; // September 30, 2020
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 19433;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateActivationParametersFromArgs(args);

        genesis = CreateGenesisBlock(1721264103, 1, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x4a6a1cc63350ee455cdf0e342adf0b01e6280d71f03b63176d09f9ba4f245743"));
        assert(genesis.hashMerkleRoot == uint256S("0x4007a33db5d9cdf2aab117335eb8431c8d13fb86e0214031fdaebe69a0f29cf7"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, uint256S("0x4a6a1cc63350ee455cdf0e342adf0b01e6280d71f03b63176d09f9ba4f245743")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,18);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,78);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,146);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "rcat";
        mweb_hrp = "tmweb";
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout, int64_t nStartHeight, int64_t nTimeoutHeight)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
        consensus.vDeployments[d].nStartHeight = nStartHeight;
        consensus.vDeployments[d].nTimeoutHeight = nTimeoutHeight;
    }
    void UpdateActivationParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateActivationParametersFromArgs(const ArgsManager& args)
{
    if (args.IsArgSet("-segwitheight")) {
        int64_t height = args.GetArg("-segwitheight", consensus.SegwitHeight);
        if (height < -1 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Activation height %ld for segwit is out of valid range. Use -1 to disable segwit.", height));
        } else if (height == -1) {
            LogPrintf("Segwit disabled for testing\n");
            height = std::numeric_limits<int>::max();
        }
        consensus.SegwitHeight = static_cast<int>(height);
    }

    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() < 3 || 5 < vDeploymentParams.size()) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end[:heightstart:heightend]");
        }
        int64_t nStartTime, nTimeout, nStartHeight, nTimeoutHeight;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        if (vDeploymentParams.size() > 3 && !ParseInt64(vDeploymentParams[3], &nStartHeight)) {
            throw std::runtime_error(strprintf("Invalid nStartHeight (%s)", vDeploymentParams[3]));
        }
        if (vDeploymentParams.size() > 4 && !ParseInt64(vDeploymentParams[4], &nTimeoutHeight)) {
            throw std::runtime_error(strprintf("Invalid nTimeoutHeight (%s)", vDeploymentParams[4]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout, nStartHeight, nTimeoutHeight);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld, start_height=%d, timeout_height=%d\n", vDeploymentParams[0], nStartTime, nTimeout, nStartHeight, nTimeoutHeight);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN) {
        return std::unique_ptr<CChainParams>(new CMainParams());
    } else if (chain == CBaseChainParams::TESTNET1) {
        return std::unique_ptr<CChainParams>(new CTestNet1Params());
    } else if (chain == CBaseChainParams::TESTNET2) {
        return std::unique_ptr<CChainParams>(new CTestNet2Params());
    } else if (chain == CBaseChainParams::TESTNET3) {
        return std::unique_ptr<CChainParams>(new CTestNet3Params());
    } else if (chain == CBaseChainParams::TESTNET4) {
        return std::unique_ptr<CChainParams>(new CTestNet4Params());
    } else if (chain == CBaseChainParams::TESTNET5) {
        return std::unique_ptr<CChainParams>(new CTestNet5Params());
    } else if (chain == CBaseChainParams::SIGNET) {
        return std::unique_ptr<CChainParams>(new CTestNet5Params()); // TODO: Support SigNet
    } else if (chain == CBaseChainParams::REGTEST) {
        return std::unique_ptr<CChainParams>(new CRegTestParams(args));
    }
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(gArgs, network);
}
