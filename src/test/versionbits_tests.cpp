// Copyright (c) 2014-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <versionbits.h>

#include <boost/test/unit_test.hpp>

/* Define a virtual block time, one block per 10 minutes after Nov 14 2014, 0:55:36am */
static int32_t TestTime(int nHeight) { return 1415926536 + 600 * nHeight; }

static const std::string StateName(ThresholdState state)
{
    switch (state) {
    case ThresholdState::DEFINED:   return "DEFINED";
    case ThresholdState::STARTED:   return "STARTED";
    case ThresholdState::LOCKED_IN: return "LOCKED_IN";
    case ThresholdState::ACTIVE:    return "ACTIVE";
    case ThresholdState::FAILED:    return "FAILED";
    } // no default case, so the compiler can warn about missing cases
    return "";
}

static const Consensus::Params paramsDummy = Consensus::Params();

class TestConditionChecker : public AbstractThresholdConditionChecker
{
private:
    mutable ThresholdConditionCache cache;
    bool height_based = false;
    int64_t height_start = 0;
    int64_t height_timeout = 0;

public:
    int64_t BeginTime(const Consensus::Params& params) const override { return this->height_based ? 0 : TestTime(10000); }
    int64_t EndTime(const Consensus::Params& params) const override { return this->height_based ? 0 : TestTime(20000); }
    int64_t BeginHeight(const Consensus::Params& params) const override { return this->height_start; }
    int64_t EndHeight(const Consensus::Params& params) const override { return this->height_timeout; }
    int Period(const Consensus::Params& params) const override { return 1000; }
    int Threshold(const Consensus::Params& params) const override { return 900; }
    bool Condition(const CBlockIndex* pindex, const Consensus::Params& params) const override { return (pindex->nVersion & 0x100); }
    void SetHeightBased(int64_t flag) { this->height_based = flag; }
    void SetHeightStart(int64_t n) { this->height_start = n; }
    void SetHeightTimeout(int64_t n) { this->height_timeout = n; }

    ThresholdState GetStateFor(const CBlockIndex* pindexPrev) const { return AbstractThresholdConditionChecker::GetStateFor(pindexPrev, paramsDummy, cache); }
    int GetStateSinceHeightFor(const CBlockIndex* pindexPrev) const { return AbstractThresholdConditionChecker::GetStateSinceHeightFor(pindexPrev, paramsDummy, cache); }
};

class TestAlwaysActiveConditionChecker : public TestConditionChecker
{
public:
    int64_t BeginTime(const Consensus::Params& params) const override { return Consensus::BIP9Deployment::ALWAYS_ACTIVE; }
};

class TestNeverActiveConditionChecker : public TestConditionChecker
{
public:
    int64_t BeginTime(const Consensus::Params& params) const override { return Consensus::BIP9Deployment::NEVER_ACTIVE; }
};

#define CHECKERS 6

class VersionBitsTester
{
    // A fake blockchain
    std::vector<CBlockIndex*> vpblock;

    // 6 independent checkers for the same bit.
    // The first one performs all checks, the second only 50%, the third only 25%, etc...
    // This is to test whether lack of cached information leads to the same results.
    TestConditionChecker checker[CHECKERS];
    // Another 6 that assume always active activation
    TestAlwaysActiveConditionChecker checker_always[CHECKERS];
    // Another 6 that assume never active activation
    TestNeverActiveConditionChecker checker_never[CHECKERS];

    // Test counter (to identify failures)
    int num;

public:
    VersionBitsTester() : num(1000) {}

    VersionBitsTester& SetCheckerHeightBasedTest(bool flag, int64_t height_start, int64_t height_timeout)
    {
        for (unsigned int i = 0; i < CHECKERS; i++) {
            checker[i].SetHeightBased(flag);
            checker[i].SetHeightStart(height_start);
            checker[i].SetHeightTimeout(height_timeout);
        }
        return *this;
    }

    VersionBitsTester& Reset() {
        // Have each group of tests be counted by the 1000s part, starting at 1000
        num = num - (num % 1000) + 1000;

        for (unsigned int i = 0; i < vpblock.size(); i++) {
            delete vpblock[i];
        }
        for (unsigned int  i = 0; i < CHECKERS; i++) {
            checker[i] = TestConditionChecker();
            checker_always[i] = TestAlwaysActiveConditionChecker();
            checker_never[i] = TestNeverActiveConditionChecker();
        }
        vpblock.clear();
        return *this;
    }

    ~VersionBitsTester() {
         Reset();
    }

    VersionBitsTester& Mine(unsigned int height, int32_t nTime, int32_t nVersion) {
        while (vpblock.size() < height) {
            CBlockIndex* pindex = new CBlockIndex();
            pindex->nHeight = vpblock.size();
            pindex->pprev = Tip();
            pindex->nTime = nTime;
            pindex->nVersion = nVersion;
            pindex->BuildSkip();
            vpblock.push_back(pindex);
        }
        return *this;
    }

    VersionBitsTester& TestStateSinceHeight(int height)
    {
        return TestStateSinceHeight(height, height);
    }

    VersionBitsTester& TestStateSinceHeight(int height, int height_delayed)
    {
        const CBlockIndex* tip = Tip();
        for (int i = 0; i < CHECKERS; i++) {
            if (InsecureRandBits(i) == 0) {
                BOOST_CHECK_MESSAGE(checker[i].GetStateSinceHeightFor(tip) == height, strprintf("Test %i for StateSinceHeight", num));
                BOOST_CHECK_MESSAGE(checker_always[i].GetStateSinceHeightFor(tip) == 0, strprintf("Test %i for StateSinceHeight (always active)", num));
                BOOST_CHECK_MESSAGE(checker_never[i].GetStateSinceHeightFor(tip) == 0, strprintf("Test %i for StateSinceHeight (never active)", num));
            }
        }
        num++;
        return *this;
    }

    VersionBitsTester& TestState(ThresholdState exp)
    {
        return TestState(exp, exp);
    }

    VersionBitsTester& TestState(ThresholdState exp, ThresholdState exp_delayed)
    {
        if (exp != exp_delayed) {
            // only expected differences are that delayed stays in locked_in longer
            BOOST_CHECK_EQUAL(exp, ThresholdState::ACTIVE);
            BOOST_CHECK_EQUAL(exp_delayed, ThresholdState::LOCKED_IN);
        }

        const CBlockIndex* pindex = Tip();
        for (int i = 0; i < CHECKERS; i++) {
            if (InsecureRandBits(i) == 0) {
                ThresholdState got = checker[i].GetStateFor(pindex);
                ThresholdState got_always = checker_always[i].GetStateFor(pindex);
                ThresholdState got_never = checker_never[i].GetStateFor(pindex);
                // nHeight of the next block. If vpblock is empty, the next (ie first)
                // block should be the genesis block with nHeight == 0.
                int height = pindex == nullptr ? 0 : pindex->nHeight + 1;
                BOOST_CHECK_MESSAGE(got == exp, strprintf("Test %i for %s height %d (got %s)", num, StateName(exp), height, StateName(got)));
                BOOST_CHECK_MESSAGE(got_always == ThresholdState::ACTIVE, strprintf("Test %i for ACTIVE height %d (got %s; always active case)", num, height, StateName(got_always)));
                BOOST_CHECK_MESSAGE(got_never == ThresholdState::FAILED, strprintf("Test %i for FAILED height %d (got %s; never active case)", num, height, StateName(got_never)));
            }
        }
        num++;
        return *this;
    }

    VersionBitsTester& TestDefined() { return TestState(ThresholdState::DEFINED); }
    VersionBitsTester& TestStarted() { return TestState(ThresholdState::STARTED); }
    VersionBitsTester& TestLockedIn() { return TestState(ThresholdState::LOCKED_IN); }
    VersionBitsTester& TestActive() { return TestState(ThresholdState::ACTIVE); }
    VersionBitsTester& TestFailed() { return TestState(ThresholdState::FAILED); }

    CBlockIndex* Tip() { return vpblock.empty() ? nullptr : vpblock.back(); }
};

BOOST_FIXTURE_TEST_SUITE(versionbits_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(versionbits_test)
{
    for (int i = 0; i < 64; i++) {
        // DEFINED -> STARTED after timeout reached -> FAILED
        VersionBitsTester().TestDefined().TestStateSinceHeight(0)
                           .Mine(1, TestTime(1), 0x100).TestDefined().TestStateSinceHeight(0)
                           .Mine(11, TestTime(11), 0x100).TestDefined().TestStateSinceHeight(0)
                           .Mine(989, TestTime(989), 0x100).TestDefined().TestStateSinceHeight(0)
                           .Mine(999, TestTime(20000), 0x100).TestDefined().TestStateSinceHeight(0) // Timeout and start time reached simultaneously
                           .Mine(1000, TestTime(20000), 0).TestStarted().TestStateSinceHeight(1000) // Hit started, stop signalling
                           .Mine(1999, TestTime(30001), 0).TestStarted().TestStateSinceHeight(1000)
                           .Mine(2000, TestTime(30002), 0x100).TestFailed().TestStateSinceHeight(2000) // Hit failed, start signalling again
                           .Mine(2001, TestTime(30003), 0x100).TestFailed().TestStateSinceHeight(2000)
                           .Mine(2999, TestTime(30004), 0x100).TestFailed().TestStateSinceHeight(2000)
                           .Mine(3000, TestTime(30005), 0x100).TestFailed().TestStateSinceHeight(2000)
                           .Mine(4000, TestTime(30006), 0x100).TestFailed().TestStateSinceHeight(2000)

        // DEFINED -> STARTED -> FAILED
                           .Reset().TestDefined().TestStateSinceHeight(0)
                           .Mine(1, TestTime(1), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(1000, TestTime(10000) - 1, 0x100).TestDefined().TestStateSinceHeight(0) // One second more and it would be defined
                           .Mine(2000, TestTime(10000), 0x100).TestStarted().TestStateSinceHeight(2000) // So that's what happens the next period
                           .Mine(2051, TestTime(10010), 0).TestStarted().TestStateSinceHeight(2000) // 51 old blocks
                           .Mine(2950, TestTime(10020), 0x100).TestStarted().TestStateSinceHeight(2000) // 899 new blocks
                           .Mine(3000, TestTime(20000), 0).TestFailed().TestStateSinceHeight(3000) // 50 old blocks (so 899 out of the past 1000)
                           .Mine(4000, TestTime(20010), 0x100).TestFailed().TestStateSinceHeight(3000)

        // DEFINED -> STARTED -> LOCKEDIN after timeout reached -> ACTIVE
                           .Reset().TestDefined().TestStateSinceHeight(0)
                           .Mine(1, TestTime(1), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(1000, TestTime(10000) - 1, 0x101).TestDefined().TestStateSinceHeight(0) // One second more and it would be defined
                           .Mine(2000, TestTime(10000), 0x101).TestStarted().TestStateSinceHeight(2000) // So that's what happens the next period
                           .Mine(2999, TestTime(30000), 0x100).TestStarted().TestStateSinceHeight(2000) // 999 new blocks
                           .Mine(3000, TestTime(30000), 0x100).TestLockedIn().TestStateSinceHeight(3000) // 1 new block (so 1000 out of the past 1000 are new)
                           .Mine(3999, TestTime(30001), 0).TestLockedIn().TestStateSinceHeight(3000)
                           .Mine(24000, TestTime(40000), 0).TestActive().TestStateSinceHeight(4000, 15000)

        // DEFINED -> STARTED -> LOCKEDIN before timeout -> ACTIVE
                           .Reset().TestDefined()
                           .Mine(1, TestTime(1), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(1000, TestTime(10000) - 1, 0x101).TestDefined().TestStateSinceHeight(0) // One second more and it would be defined
                           .Mine(2000, TestTime(10000), 0x101).TestStarted().TestStateSinceHeight(2000) // So that's what happens the next period
                           .Mine(2050, TestTime(10010), 0x200).TestStarted().TestStateSinceHeight(2000) // 50 old blocks
                           .Mine(2950, TestTime(10020), 0x100).TestStarted().TestStateSinceHeight(2000) // 900 new blocks
                           .Mine(2999, TestTime(19999), 0x200).TestStarted().TestStateSinceHeight(2000) // 49 old blocks
                           .Mine(3000, TestTime(29999), 0x200).TestLockedIn().TestStateSinceHeight(3000) // 1 old block (so 900 out of the past 1000)
                           .Mine(3999, TestTime(30001), 0).TestLockedIn().TestStateSinceHeight(3000)
                           .Mine(15000, TestTime(40000), 0).TestActive().TestStateSinceHeight(4000, 15000)
                           .Mine(24000, TestTime(40000), 0).TestActive().TestStateSinceHeight(4000, 15000)

        // DEFINED multiple periods -> STARTED multiple periods -> FAILED
                           .Reset().TestDefined().TestStateSinceHeight(0)
                           .Mine(999, TestTime(999), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(1000, TestTime(1000), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(2000, TestTime(2000), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(3000, TestTime(10000), 0).TestStarted().TestStateSinceHeight(3000)
                           .Mine(4000, TestTime(10000), 0).TestStarted().TestStateSinceHeight(3000)
                           .Mine(5000, TestTime(10000), 0).TestStarted().TestStateSinceHeight(3000)
                           .Mine(5999, TestTime(20000), 0).TestStarted().TestStateSinceHeight(3000)
                           .Mine(6000, TestTime(20000), 0).TestFailed().TestStateSinceHeight(6000)
                           .Mine(7000, TestTime(20000), 0x100).TestFailed().TestStateSinceHeight(6000)
                           .Mine(24000, TestTime(20000), 0x100).TestFailed().TestStateSinceHeight(6000) // stay in FAILED no matter how much we signal

        // DEFINED -> STARTED -> LOCKEDIN -> ACTIVE (mandatory lockin)
                           .Reset().SetCheckerHeightBasedTest(true, 2000, 4000).TestDefined().TestStateSinceHeight(0)
                           .Mine(999, TestTime(999), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(1000, TestTime(1000), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(2000, TestTime(10000), 0).TestStarted().TestStateSinceHeight(2000)
                           .Mine(4000, TestTime(10001), 0).TestLockedIn().TestStateSinceHeight(4000)
                           .Mine(5000, TestTime(10002), 0).TestActive().TestStateSinceHeight(5000)
                           .Mine(7000, TestTime(20000), 0x100).TestActive().TestStateSinceHeight(5000)

        // DEFINED -> STARTED -> LOCKEDIN -> ACTIVE (mandatory lockin but activation by signalling)
                           .Reset().SetCheckerHeightBasedTest(true, 3000, 10000).TestDefined().TestStateSinceHeight(0)
                           .Mine(1, TestTime(1), 0x200).TestDefined().TestStateSinceHeight(0)
                           .Mine(1000, TestTime(9999) - 1, 0x200).TestDefined().TestStateSinceHeight(0)
                           .Mine(2000, TestTime(10000), 0x101).TestDefined().TestStateSinceHeight(0)
                           .Mine(3000, TestTime(10010), 0x200).TestStarted().TestStateSinceHeight(3000)
                           .Mine(3050, TestTime(10020), 0x200).TestStarted().TestStateSinceHeight(3000) // 50 old blocks
                           .Mine(3950, TestTime(11999), 0x100).TestStarted().TestStateSinceHeight(3000) // 900 new blocks
                           .Mine(3999, TestTime(12000), 0x200).TestStarted().TestStateSinceHeight(3000) // 49 old blocks
                           .Mine(4000, TestTime(12500), 0x200).TestLockedIn().TestStateSinceHeight(4000) // 1 old block
                           .Mine(4999, TestTime(13000), 0).TestLockedIn().TestStateSinceHeight(4000)
                           .Mine(5000, TestTime(13001), 0).TestActive().TestStateSinceHeight(5000)
        ;
    }
}

BOOST_AUTO_TEST_CASE(versionbits_sanity)
{
    // Sanity checks of version bit deployments
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    const Consensus::Params &mainnetParams = chainParams->GetConsensus();
    for (int i=0; i<(int) Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
        uint32_t bitmask = VersionBitsMask(mainnetParams, static_cast<Consensus::DeploymentPos>(i));
        // Make sure that no deployment tries to set an invalid bit.
        BOOST_CHECK_EQUAL(bitmask & ~(uint32_t)VERSIONBITS_TOP_MASK, bitmask);

        // Check start height is on a retarget boundary
        BOOST_CHECK_EQUAL(mainnetParams.vDeployments[i].nStartHeight % mainnetParams.nMinerConfirmationWindow, 0U);
        // Check start_height is 0 for ALWAYS_ACTIVE and never active deployments
        if (mainnetParams.vDeployments[i].nStartTime == Consensus::BIP9Deployment::ALWAYS_ACTIVE || mainnetParams.vDeployments[i].nStartTime == Consensus::BIP9Deployment::NEVER_ACTIVE) {
            BOOST_CHECK_EQUAL(mainnetParams.vDeployments[i].nStartHeight, 0);
            BOOST_CHECK_EQUAL(mainnetParams.vDeployments[i].nTimeoutHeight, 0);
        }

        // Verify that the deployment windows of different deployment using the
        // same bit are disjoint.
        // This test may need modification at such time as a new deployment
        // is proposed that reuses the bit of an activated soft fork, before the
        // end time of that soft fork.  (Alternatively, the end time of that
        // activated soft fork could be later changed to be earlier to avoid
        // overlap.)
        for (int j=i+1; j<(int) Consensus::MAX_VERSION_BITS_DEPLOYMENTS; j++) {
            if (VersionBitsMask(mainnetParams, static_cast<Consensus::DeploymentPos>(j)) == bitmask) {
                BOOST_CHECK(mainnetParams.vDeployments[j].nStartTime > mainnetParams.vDeployments[i].nTimeout ||
                        mainnetParams.vDeployments[i].nStartTime > mainnetParams.vDeployments[j].nTimeout);
            }
        }
    }
}

/** Check that ComputeBlockVersion will set the appropriate bit correctly for BIP8 (height-based) activation */
static void check_computeblockversion_bip8(const Consensus::Params& params, Consensus::DeploymentPos dep)
{
    // nStartTime and nTimeout must be set to 0 to use BIP8
    BOOST_CHECK(params.vDeployments[dep].nStartTime == 0 && params.vDeployments[dep].nTimeout == 0);

    int64_t bit = params.vDeployments[dep].bit;
    int32_t bit_mask = (1 << bit);
    int64_t nStartHeight = params.vDeployments[dep].nStartHeight;
    int64_t nTimeoutHeight = params.vDeployments[dep].nTimeoutHeight;
    uint32_t nMinerConfirmationWindow = params.nMinerConfirmationWindow;

    // should not be any signalling for first block
    BOOST_CHECK_EQUAL(ComputeBlockVersion(nullptr, params), VERSIONBITS_TOP_BITS);

    BOOST_CHECK(nStartHeight >= 0);
    BOOST_CHECK_EQUAL(nStartHeight % nMinerConfirmationWindow, 0U);

    BOOST_CHECK(nTimeoutHeight <= std::numeric_limits<uint32_t>::max());
    BOOST_CHECK_EQUAL(nTimeoutHeight % nMinerConfirmationWindow, 0U);

    BOOST_CHECK(0 <= bit && bit < 32);
    BOOST_CHECK((bit_mask & VERSIONBITS_TOP_MASK) == 0);

    int64_t nTime = 100000;

    const CBlockIndex* lastBlock = nullptr;

    {
        // In the first chain, we don't set the bit, and wait for forced activation via timeout.
        // The bit should be set by CBV during range [nStartHeight, nTimeoutHeight + nMinerConfirmationWindow)
        VersionBitsTester chain;
        versionbitscache.Clear();

        // Bit should not be set before nStartHeight
        lastBlock = chain.Mine(nStartHeight - 1, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
        BOOST_CHECK_EQUAL(ComputeBlockVersion(lastBlock, params) & bit_mask, 0);

        // Once we hit nStartHeight, the feature switches to STARTED, we should be able to signal for activation.
        for (uint32_t i = nStartHeight; i < nTimeoutHeight; i++) {
            lastBlock = chain.Mine(i, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
            BOOST_CHECK((ComputeBlockVersion(lastBlock, params) & bit_mask) != 0);
            BOOST_CHECK_EQUAL(ComputeBlockVersion(lastBlock, params) & VERSIONBITS_TOP_MASK, VERSIONBITS_TOP_BITS);
            BOOST_CHECK_EQUAL(VersionBitsState(lastBlock, params, dep, versionbitscache), ThresholdState::STARTED);
        }

        // Once the timeout height is hit, the feature switches to LOCKED_IN for 1 full miner confirmation window
        for (uint32_t i = 0; i < nMinerConfirmationWindow; i++) {
            lastBlock = chain.Mine(nTimeoutHeight + i, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
            BOOST_CHECK((ComputeBlockVersion(lastBlock, params) & bit_mask) != 0);
            BOOST_CHECK_EQUAL(ComputeBlockVersion(lastBlock, params) & VERSIONBITS_TOP_MASK, VERSIONBITS_TOP_BITS);
            BOOST_CHECK_EQUAL(VersionBitsState(lastBlock, params, dep, versionbitscache), ThresholdState::LOCKED_IN);
        }

        // After 1 full confirmation window, the feature should be ACTIVE, so we should stop setting the bit.
        lastBlock = chain.Mine(nTimeoutHeight + nMinerConfirmationWindow, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
        BOOST_CHECK_EQUAL(ComputeBlockVersion(lastBlock, params) & bit_mask, 0);
        BOOST_CHECK_EQUAL(VersionBitsState(lastBlock, params, dep, versionbitscache), ThresholdState::ACTIVE);
    }

    {
        // In the second chain, we set the bit to activate before forced activation at nTimeoutHeight.
        // We will signal for the feature during the first confirmation window.
        // It should be LOCKED-IN for the 2nd window, after which it switches to ACTIVE.
        // The bit should be set by CBV while STARTED and LOCKED-IN, and then no longer set while ACTIVE.
        // That is, it should be set by CBV during range [nStartHeight, nStartHeight + 2 * nMinerConfirmationWindow)
        VersionBitsTester chain;
        versionbitscache.Clear();

        // Bit should not be set before nStartHeight
        lastBlock = chain.Mine(nStartHeight - 1, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
        BOOST_CHECK_EQUAL(ComputeBlockVersion(lastBlock, params) & bit_mask, 0);
        BOOST_CHECK_EQUAL(VersionBitsState(lastBlock, params, dep, versionbitscache), ThresholdState::DEFINED);

        // Once we hit nStartHeight, the feature switches to STARTED, and we start signaling for activation.
        for (uint32_t i = 0; i < nMinerConfirmationWindow; i++) {
            lastBlock = chain.Mine(nStartHeight + i, nTime, VERSIONBITS_TOP_BITS | bit_mask).Tip();
            BOOST_CHECK((ComputeBlockVersion(lastBlock, params) & bit_mask) != 0);
            BOOST_CHECK_EQUAL(ComputeBlockVersion(lastBlock, params) & VERSIONBITS_TOP_MASK, VERSIONBITS_TOP_BITS);
            BOOST_CHECK_EQUAL(VersionBitsState(lastBlock, params, dep, versionbitscache), ThresholdState::STARTED);
        }

        // After the first confirmation window, the feature switches to LOCKED-IN for 1 full miner confirmation window.
        for (uint32_t i = 0; i < nMinerConfirmationWindow; i++) {
            lastBlock = chain.Mine(nStartHeight + nMinerConfirmationWindow + i, nTime, VERSIONBITS_TOP_BITS | bit_mask).Tip();
            BOOST_CHECK((ComputeBlockVersion(lastBlock, params) & bit_mask) != 0);
            BOOST_CHECK_EQUAL(ComputeBlockVersion(lastBlock, params) & VERSIONBITS_TOP_MASK, VERSIONBITS_TOP_BITS);
            BOOST_CHECK_EQUAL(VersionBitsState(lastBlock, params, dep, versionbitscache), ThresholdState::LOCKED_IN);
        }

        // After 1 full LOCKED-IN confirmation window, the feature should be ACTIVE, so we should stop setting the bit.
        lastBlock = chain.Mine(nStartHeight + (2 * nMinerConfirmationWindow), nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
        BOOST_CHECK_EQUAL(ComputeBlockVersion(lastBlock, params) & bit_mask, 0);
        BOOST_CHECK_EQUAL(VersionBitsState(lastBlock, params, dep, versionbitscache), ThresholdState::ACTIVE);
    }
}

/** Check that ComputeBlockVersion will set the appropriate bit correctly */
static void check_computeblockversion(const Consensus::Params& params, Consensus::DeploymentPos dep)
{
    // This implicitly uses versionbitscache, so clear it every time
    versionbitscache.Clear();

    int64_t bit = params.vDeployments[dep].bit;
    int64_t nStartTime = params.vDeployments[dep].nStartTime;
    int64_t nTimeout = params.vDeployments[dep].nTimeout;

    if (nStartTime == 0 && nTimeout == 0) {
        return check_computeblockversion_bip8(params, dep);
    }

    // should not be any signalling for first block
    BOOST_CHECK_EQUAL(ComputeBlockVersion(nullptr, params), VERSIONBITS_TOP_BITS);

    // always/never active deployments shouldn't need to be tested further
    if (nStartTime == Consensus::BIP9Deployment::ALWAYS_ACTIVE) return;
    if (nStartTime == Consensus::BIP9Deployment::NEVER_ACTIVE) return;

    BOOST_CHECK(nStartTime < nTimeout);
    BOOST_CHECK(nStartTime >= 0);
    BOOST_CHECK(nTimeout <= std::numeric_limits<uint32_t>::max() || nTimeout == Consensus::BIP9Deployment::NO_TIMEOUT);
    BOOST_CHECK(0 <= bit && bit < 32);
    BOOST_CHECK(((1 << bit) & VERSIONBITS_TOP_MASK) == 0);

    // In the first chain, test that the bit is set by CBV until it has failed.
    // In the second chain, test the bit is set by CBV while STARTED and
    // LOCKED-IN, and then no longer set while ACTIVE.
    VersionBitsTester firstChain, secondChain;

    int64_t nTime = nStartTime;

    const CBlockIndex *lastBlock = nullptr;

    // Before MedianTimePast of the chain has crossed nStartTime, the bit
    // should not be set.
    if (nTime == 0) {
        // since CBlockIndex::nTime is uint32_t we can't represent any
        // earlier time, so will transition from DEFINED to STARTED at the
        // end of the first period by mining blocks at nTime == 0
        lastBlock = firstChain.Mine(params.nMinerConfirmationWindow - 1, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
        BOOST_CHECK_EQUAL(ComputeBlockVersion(lastBlock, params) & (1<<bit), 0);
        lastBlock = firstChain.Mine(params.nMinerConfirmationWindow, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
        BOOST_CHECK((ComputeBlockVersion(lastBlock, params) & (1<<bit)) != 0);
        // then we'll keep mining at nStartTime...
    } else {
        // use a time 1s earlier than start time to check we stay DEFINED
        --nTime;

        // Start generating blocks before nStartTime
        lastBlock = firstChain.Mine(params.nMinerConfirmationWindow, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
        BOOST_CHECK_EQUAL(ComputeBlockVersion(lastBlock, params) & (1<<bit), 0);

        // Mine more blocks (4 less than the adjustment period) at the old time, and check that CBV isn't setting the bit yet.
        for (uint32_t i = 1; i < params.nMinerConfirmationWindow - 4; i++) {
            lastBlock = firstChain.Mine(params.nMinerConfirmationWindow + i, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
            BOOST_CHECK_EQUAL(ComputeBlockVersion(lastBlock, params) & (1<<bit), 0);
        }
        // Now mine 5 more blocks at the start time -- MTP should not have passed yet, so
        // CBV should still not yet set the bit.
        nTime = nStartTime;
        for (uint32_t i = params.nMinerConfirmationWindow - 4; i <= params.nMinerConfirmationWindow; i++) {
            lastBlock = firstChain.Mine(params.nMinerConfirmationWindow + i, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
            BOOST_CHECK_EQUAL(ComputeBlockVersion(lastBlock, params) & (1<<bit), 0);
        }
        // Next we will advance to the next period and transition to STARTED,
    }

    lastBlock = firstChain.Mine(params.nMinerConfirmationWindow * 3, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
    // so ComputeBlockVersion should now set the bit,
    BOOST_CHECK((ComputeBlockVersion(lastBlock, params) & (1<<bit)) != 0);
    // and should also be using the VERSIONBITS_TOP_BITS.
    BOOST_CHECK_EQUAL(ComputeBlockVersion(lastBlock, params) & VERSIONBITS_TOP_MASK, VERSIONBITS_TOP_BITS);

    // Check that ComputeBlockVersion will set the bit until nTimeout
    nTime += 600;
    uint32_t blocksToMine = params.nMinerConfirmationWindow * 2; // test blocks for up to 2 time periods
    uint32_t nHeight = params.nMinerConfirmationWindow * 3;
    // These blocks are all before nTimeout is reached.
    while (nTime < nTimeout && blocksToMine > 0) {
        lastBlock = firstChain.Mine(nHeight+1, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
        BOOST_CHECK((ComputeBlockVersion(lastBlock, params) & (1<<bit)) != 0);
        BOOST_CHECK_EQUAL(ComputeBlockVersion(lastBlock, params) & VERSIONBITS_TOP_MASK, VERSIONBITS_TOP_BITS);
        blocksToMine--;
        nTime += 600;
        nHeight += 1;
    }

    if (nTimeout != Consensus::BIP9Deployment::NO_TIMEOUT) {
        // can reach any nTimeout other than NO_TIMEOUT due to earlier BOOST_REQUIRE

        nTime = nTimeout;

        // finish the last period before we start timing out
        while (nHeight % params.nMinerConfirmationWindow != 0) {
            lastBlock = firstChain.Mine(nHeight+1, nTime - 1, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
            BOOST_CHECK((ComputeBlockVersion(lastBlock, params) & (1<<bit)) != 0);
            nHeight += 1;
        }

        // FAILED is only triggered at the end of a period, so CBV should be setting
        // the bit until the period transition.
        for (uint32_t i = 0; i < params.nMinerConfirmationWindow - 1; i++) {
            lastBlock = firstChain.Mine(nHeight+1, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
            BOOST_CHECK((ComputeBlockVersion(lastBlock, params) & (1<<bit)) != 0);
            nHeight += 1;
        }
        // The next block should trigger no longer setting the bit.
        lastBlock = firstChain.Mine(nHeight+1, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
        BOOST_CHECK_EQUAL(ComputeBlockVersion(lastBlock, params) & (1<<bit), 0);
    }

    // On a new chain:
    // verify that the bit will be set after lock-in, and then stop being set
    // after activation.
    nTime = nStartTime;

    // Mine one period worth of blocks, and check that the bit will be on for the
    // next period.
    lastBlock = secondChain.Mine(params.nMinerConfirmationWindow, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
    BOOST_CHECK((ComputeBlockVersion(lastBlock, params) & (1<<bit)) != 0);

    // Mine another period worth of blocks, signaling the new bit.
    lastBlock = secondChain.Mine(params.nMinerConfirmationWindow * 2, nTime, VERSIONBITS_TOP_BITS | (1<<bit)).Tip();
    // After one period of setting the bit on each block, it should have locked in.
    // We keep setting the bit for one more period though, until activation.
    BOOST_CHECK((ComputeBlockVersion(lastBlock, params) & (1<<bit)) != 0);

    // Now check that we keep mining the block until the end of this period, and
    // then stop at the beginning of the next period.
    lastBlock = secondChain.Mine((params.nMinerConfirmationWindow * 3) - 1, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();
    BOOST_CHECK((ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);
    lastBlock = secondChain.Mine(params.nMinerConfirmationWindow * 3, nTime, VERSIONBITS_LAST_OLD_BLOCK_VERSION).Tip();

    // Check that we don't signal after activation
    BOOST_CHECK_EQUAL(ComputeBlockVersion(lastBlock, params) & (1<<bit), 0);
}

BOOST_AUTO_TEST_CASE(versionbits_computeblockversion)
{
    // check that any deployment on any chain can conceivably reach both
    // ACTIVE and FAILED states in roughly the way we expect
    for (const auto& chain_name : { CBaseChainParams::MAIN, CBaseChainParams::TESTNET1, CBaseChainParams::TESTNET2, CBaseChainParams::TESTNET3, CBaseChainParams::TESTNET4, CBaseChainParams::TESTNET5, CBaseChainParams::REGTEST}) {
        const auto chainParams = CreateChainParams(*m_node.args, chain_name);
        for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++i) {
            check_computeblockversion(chainParams->GetConsensus(), static_cast<Consensus::DeploymentPos>(i));
        }
    }

    {
        // Use regtest/testdummy to ensure we always exercise some
        // deployment that's not always/never active
        ArgsManager args;
        args.ForceSetArg("-vbparams", "testdummy:1199145601:1230767999"); // January 1, 2008 - December 31, 2008
        const auto chainParams = CreateChainParams(args, CBaseChainParams::REGTEST);
        check_computeblockversion(chainParams->GetConsensus(), Consensus::DEPLOYMENT_TESTDUMMY);
    }

}

BOOST_AUTO_TEST_SUITE_END()