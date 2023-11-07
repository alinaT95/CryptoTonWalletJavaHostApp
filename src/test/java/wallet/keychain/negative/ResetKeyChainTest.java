package wallet.keychain.negative;

import org.junit.Assert;
import org.junit.Test;
import wallet.tonWalletApi.WalletHostAPI;
import wallet.common.ByteArrayHelper;
import wallet.keychain.KeyChainBaseTest;
import wallet.smartcard.utils.HmacHelper;

import static wallet.common.ByteArrayHelper.hex;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.*;

import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.bConcat;
import static wallet.smartcard.utils.HmacHelper.computeMac;

public class ResetKeyChainTest extends KeyChainBaseTest {
    public static final int NUM_OF_ITER = 10;
    public static final int RESET_KEYCHAIN_CORRECT_INPUT_LENGTH = 64;

    @Test
    public void testIncorrectSault() throws Exception {
        addKeys();
        testKeyMiscData();
        byte[] sault = new byte[SAULT_LENGTH];
        HmacHelper.setIsCorrrectKey(true);
        for(int i = 0; i < NUM_OF_ITER; i++){
            System.out.println("Iter = " + i);
            try {
                random.nextBytes(sault);
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                WalletHostAPI.getWalletCardReaderWrapper().resetKeyChain(bConcat(sault, computeMac(sault)));
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_SAULT)));
            }
        }
        testResetKeyChain();
        testKeyMiscData();
    }

    @Test
    public void testWrongLength() throws Exception{
        addKeys();
        testKeyMiscData();
        for(int len = 0; len <= 255; len++){
            System.out.println("Iter = " + len);
            if(len == RESET_KEYCHAIN_CORRECT_INPUT_LENGTH) continue;
            byte[] data = new byte[len];
            try {
                random.nextBytes(data);
                System.out.println("data = " + ByteArrayHelper.hex(data));
                WalletHostAPI.getWalletCardReaderWrapper().resetKeyChain(data);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
        testResetKeyChain();
        testKeyMiscData();
    }

    @Test
    public void testOneIncorrectMac() throws Exception{
        addKeys();
        testKeyMiscData();
        HmacHelper.setIsCorrrectKey(false);
        try {
            walletHostAPI.resetKeyChain();
            assertTrue(false);
        }
        catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_APDU_HMAC)));
        }

        HmacHelper.setIsCorrrectKey(true);
        testResetKeyChain();
        testKeyMiscData();
    }

    @Test
    public void testBlockingBecauseOfMacFailing() throws Exception{
        addKeys();
        testKeyMiscData();
        HmacHelper.setIsCorrrectKey(false);
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                try {
                    walletHostAPI.resetKeyChain();
                    Assert.assertTrue(false);
                } catch (Exception e) {
                    e.printStackTrace();
                    Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_APDU_HMAC)) || e.getMessage().contains(ByteArrayHelper.hex(SW_HMAC_VERIFICATION_TRIES_EXPIRED)));
                }
            }
            else {
                break;
            }
        }
        appletStateChecker.checkBlockedState();
    }

    // INSTRUCTION: Before calling each testHelper method here you should reinstall applet in JCIDE simulator, do not run other tests before this testHelper
    @Test
    public void testNotBlockingAndSuccessfullSigningAfterMacFailing() throws Exception {
        addKeys();
        testKeyMiscData();
        HmacHelper.setIsCorrrectKey(false);
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES - 1; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                try {
                    walletHostAPI.resetKeyChain();
                    Assert.assertTrue(false);
                } catch (Exception e) {
                    e.printStackTrace();
                    Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_APDU_HMAC)));
                }
            }
            else {
                break;
            }
        }

        HmacHelper.setIsCorrrectKey(true);
        testResetKeyChain();
    }

    // INSTRUCTION: Before calling each testHelper method here you should reinstall applet in JCIDE simulator, do not run other tests before this testHelper
    @Test
    public void testHmacVerificationFailCounterClearing() throws Exception {
        testOneIncorrectMac();
        HmacHelper.setIsCorrrectKey(true);
        testResetKeyChain();
        testNotBlockingAndSuccessfullSigningAfterMacFailing();
    }
}
