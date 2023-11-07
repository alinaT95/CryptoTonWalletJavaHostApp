package wallet.keychain.negative;

import org.junit.Assert;
import org.junit.Test;
import wallet.tonWalletApi.WalletHostAPI;
import wallet.common.ByteArrayHelper;
import wallet.smartcard.utils.HmacHelper;

import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.bConcat;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.WalletAppletConstants.APP_PERSONALIZED;
import static wallet.smartcard.WalletAppletConstants.MAX_HMAC_FAIL_TRIES;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.*;
import static wallet.smartcard.utils.HmacHelper.computeMac;

public class GetHmacTest extends KeyChainImmutabilityBaseTest {
    public static final int NUM_OF_ITER = 10;
    public static final int GET_HMAC_CORRECT_LC = 66;
    public static final byte GET_HMAC_SIZE_CORRECT_LE = 34;

    @Test
    public void testIncorrectSault() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        byte[] sault = new byte[SAULT_LENGTH];
        byte[] ind = new byte[]{0, 0};
        for(int i = 0; i < NUM_OF_ITER; i++){
            System.out.println("Iter = " + i);
            try {
                random.nextBytes(sault);
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] dataChunk = bConcat(ind, sault);
                WalletHostAPI.getWalletCardReaderWrapper().getHmac(bConcat(dataChunk, computeMac(dataChunk)), GET_HMAC_SIZE_CORRECT_LE);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_SAULT)));
            }
        }
    }

    @Test
    public void testWrongLengthLc() throws Exception {
        for(int length = 0; length <= 255; length++){
            System.out.println("Length = " + length);
            if(length == GET_HMAC_CORRECT_LC) continue;
            byte[] data = new byte[length];
            try {
                random.nextBytes(data);
                System.out.println("data = " + ByteArrayHelper.hex(data));
                WalletHostAPI.getWalletCardReaderWrapper().getHmac(data, GET_HMAC_SIZE_CORRECT_LE);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
    }

    @Test
    public void testWrongLengthLe() throws Exception {
        byte[] index = new byte[]{0, 0};
        HmacHelper.setIsCorrrectKey(true);
        for(int le = 0; le <= 255; le++){
            if(le == GET_HMAC_SIZE_CORRECT_LE) continue;
            System.out.println("Le = " + le);
            byte[] sault = walletHostAPI.getSault();
            byte[] mac = computeMac(bConcat(index, sault));
            try {
                WalletHostAPI.getWalletCardReaderWrapper().getHmac(bConcat(index, sault, mac), (byte) le);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
    }


    @Test
    public void testOneIncorrectMac() throws Exception{
        HmacHelper.setIsCorrrectKey(false);
        byte[] ind = new byte[]{0, 0};
        try {
            WalletHostAPI.getTonWalletApi().getHmac(ind);
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
                    WalletHostAPI.getTonWalletApi().getHmac(ind);
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
                    WalletHostAPI.getTonWalletApi().getHmac(ind);
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
        testHmacsSync();
        testNotBlockingAndSuccessfullSigningAfterMacFailing();
    }

    @Test
    public void testIndOutOfBound() throws Exception {
        //a) 7F00 — run the command for some ind ≥ numberOfKeys.
        //int numOfKeys = getNumberOfKeys();
        HmacHelper.setIsCorrrectKey(true);
        int numberOfKeys = walletHostAPI.getNumberOfKeys();
        System.out.println("numberOfKeys = " + numberOfKeys);
        byte[] ind = new byte[2];
        ByteArrayHelper.setShort(ind, (short)0, (short)(numberOfKeys + 1));
        try {
            WalletHostAPI.getTonWalletApi().getHmac(ind);
            assertTrue(false);
        }
        catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_KEY_INDEX )));
        }
    }
}
