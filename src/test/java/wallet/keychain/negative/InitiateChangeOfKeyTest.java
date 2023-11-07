package wallet.keychain.negative;

import org.junit.Assert;
import org.junit.Test;
import wallet.tonWalletApi.WalletHostAPI;
import wallet.common.ByteArrayHelper;
import wallet.smartcard.utils.HmacHelper;

import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.bConcat;
import static wallet.smartcard.WalletAppletConstants.APP_PERSONALIZED;
import static wallet.smartcard.WalletAppletConstants.MAX_HMAC_FAIL_TRIES;
import static wallet.smartcard.WalletAppletConstants.SAULT_LENGTH;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.*;
import static wallet.smartcard.utils.HmacHelper.computeMac;

public class InitiateChangeOfKeyTest extends KeyChainImmutabilityBaseTest {
    public static final int GET_INITIATECHANGE_OF_KEY_LC = 66;
    public static final int NUM_OF_ITER = 10;

    @Test
    public void testPositive() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        int numberOfKeys = walletHostAPI.getNumberOfKeys();
        for(int i = 0; i < NUM_OF_ITER; i++){
            int ind = random.nextInt(numberOfKeys);
            WalletHostAPI.getTonWalletApi().initiateChangeOfKey( ByteArrayHelper.bytesForShort((short)ind));
        }
    }

    @Test
    public void testIncorrectSault() throws Exception {
        byte[] sault = new byte[SAULT_LENGTH];
        HmacHelper.setIsCorrrectKey(true);
        for(int i = 0; i < NUM_OF_ITER; i++){
            System.out.println("Iter = " + i);
            try {
                random.nextBytes(sault);
                byte[] ind = new byte[]{0, 0};
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] dataChunk = bConcat(new byte[]{ind[0], ind[1]}, sault);
                WalletHostAPI.getWalletCardReaderWrapper().initiateChangeOfKey((bConcat(dataChunk, computeMac(dataChunk))));
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_SAULT)));
            }
        }
    }

    @Test
    public void testWrongLength() throws Exception {
        for(int length = 0; length <= 255; length++){
            System.out.println("Length = " + length);
            if(length == GET_INITIATECHANGE_OF_KEY_LC) continue;
            byte[] wrongData = new byte[length];
            try {
                random.nextBytes(wrongData);
                System.out.println("bad data = " + ByteArrayHelper.hex(wrongData));
                WalletHostAPI.getWalletCardReaderWrapper().initiateChangeOfKey(wrongData);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
    }

    @Test
    public void testIndexOutOfBound() throws Exception{
        // 7F00 — run the command for some ind ≥ numberOfKeys.
        int numberOfKeys = walletHostAPI.getNumberOfKeys();
        try {
            WalletHostAPI.getTonWalletApi().initiateChangeOfKey( ByteArrayHelper.bytesForShort((short)(numberOfKeys + 1)));
            assertTrue(false);
        }
        catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_KEY_INDEX)));
        }
    }

    @Test
    public void testOneIncorrectMac() throws Exception{
        HmacHelper.setIsCorrrectKey(false);
        byte[] ind = new byte[]{0, 0};
        try {
            WalletHostAPI.getTonWalletApi().initiateChangeOfKey(ind);
            assertTrue(false);
        }
        catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_APDU_HMAC)));
        }

        HmacHelper.setIsCorrrectKey(true);
    }


    @Test
    public void testBlockingBecauseOfMacFailing() throws Exception {
        HmacHelper.setIsCorrrectKey(false);
        byte[] ind = new byte[]{0, 0};
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                try {
                    WalletHostAPI.getTonWalletApi().initiateChangeOfKey(ind);
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
        HmacHelper.setIsCorrrectKey(false);
        byte[] ind = new byte[]{0, 0};
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES - 1; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                try {
                    WalletHostAPI.getTonWalletApi().initiateChangeOfKey(ind);
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
    }

    // INSTRUCTION: Before calling each testHelper method here you should reinstall applet in JCIDE simulator, do not run other tests before this testHelper
    @Test
    public void testHmacVerificationFailCounterClearing() throws Exception {
        testOneIncorrectMac();
        HmacHelper.setIsCorrrectKey(true);
        testPositive();
        testNotBlockingAndSuccessfullSigningAfterMacFailing();
    }

}
