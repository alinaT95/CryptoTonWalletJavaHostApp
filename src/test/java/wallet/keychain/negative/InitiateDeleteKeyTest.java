package wallet.keychain.negative;

import org.junit.Assert;
import org.junit.Test;
import wallet.tonWalletApi.WalletHostAPI;
import wallet.common.ByteArrayHelper;
import wallet.smartcard.utils.HmacHelper;

import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.bConcat;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.utils.HmacHelper.computeMac;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.*;

public class InitiateDeleteKeyTest extends KeyChainImmutabilityBaseTest {
    public static final int INITIATE_DELETE_KEY_LC = 66;
    public static final int NUM_OF_ITER = 100;

    @Test
    public void testPositive() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        int numberOfKeys = walletHostAPI.getNumberOfKeys();
        int ind = random.nextInt(numberOfKeys);
        WalletHostAPI.getTonWalletApi().initiateDeleteOfKey( ByteArrayHelper.bytesForShort((short)ind));
        assertTrue(walletHostAPI.getAppletState() == APP_DELETE_KEY_FROM_KEYCHAIN_MODE);
        try {
            WalletHostAPI.getTonWalletApi().initiateDeleteOfKey( ByteArrayHelper.bytesForShort((short)ind));
        }
        catch (Exception e){
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INS_NOT_SUPPORTED)));
        }
       // walletHostAPI.resetKeyChain();
    }

    @Test
    public void testIncorrectSault() throws Exception {
        byte[] sault = new byte[SAULT_LENGTH];
        HmacHelper.setIsCorrrectKey(true);
        int numberOfKeys = walletHostAPI.getNumberOfKeys();
        for(int i = 0; i < NUM_OF_ITER; i++){
            System.out.println("Iter = " + i);
            try {
                random.nextBytes(sault);
                short ind = (short) random.nextInt(numberOfKeys);
                byte[] indBytes = ByteArrayHelper.bytesForShort(ind);
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                System.out.println("ind = " + ind);
                byte[] dataChunk = bConcat(new byte[]{indBytes[0], indBytes [1]}, sault);
                WalletHostAPI.getWalletCardReaderWrapper().initiateDeleteOfKey(bConcat(dataChunk, computeMac(dataChunk)), INITIATE_DELETE_KEY_LE);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_SAULT)));
            }
        }
        assertTrue(walletHostAPI.getAppletState() == APP_PERSONALIZED);
    }

    @Test
    public void testWrongLengthLc() throws Exception {
        for(int length = 0; length <= 255; length++){
            System.out.println("Length = " + length);
            if(length == INITIATE_DELETE_KEY_LC) continue;
            byte[] data = new byte[length];
            try {
                random.nextBytes(data);
                System.out.println("data = " + ByteArrayHelper.hex(data));
                WalletHostAPI.getWalletCardReaderWrapper().initiateDeleteOfKey(data, INITIATE_DELETE_KEY_LE);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
        assertTrue(walletHostAPI.getAppletState() == APP_PERSONALIZED);
    }

    @Test
    public void testWrongLengthLe() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        int numberOfKeys = walletHostAPI.getNumberOfKeys();
        for(int le = 0; le <= 255; le++){
            if(le == INITIATE_DELETE_KEY_LE) continue;
            System.out.println("Le = " + le);
            byte[] sault = walletHostAPI.getSault();
            short ind = (short) random.nextInt(numberOfKeys);
            byte[] indBytes = ByteArrayHelper.bytesForShort(ind);
            System.out.println("sault = " + ByteArrayHelper.hex(sault));
            System.out.println("ind = " + ind);
            byte[] dataChunk = bConcat(new byte[]{indBytes[0], indBytes [1]}, sault);
            try {
                WalletHostAPI.getWalletCardReaderWrapper().initiateDeleteOfKey(bConcat(dataChunk, computeMac(dataChunk)), (byte) le);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
        assertTrue(walletHostAPI.getAppletState() == APP_PERSONALIZED);
    }

    @Test
    public void testIndexOutOfBound() throws Exception{
        // 7F00 — run the command for some ind ≥ numberOfKeys.
        int numberOfKeys = walletHostAPI.getNumberOfKeys();
        try {
            WalletHostAPI.getTonWalletApi().initiateDeleteOfKey( ByteArrayHelper.bytesForShort((short)(numberOfKeys + 1)));
            assertTrue(false);
        }
        catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_KEY_INDEX )));
        }
    }

    @Test
    public void testOneIncorrectMac() throws Exception{
        int numberOfKeys = walletHostAPI.getNumberOfKeys();
        HmacHelper.setIsCorrrectKey(false);
        short ind = (short) random.nextInt(numberOfKeys);
        try {
            WalletHostAPI.getTonWalletApi().initiateDeleteOfKey(ByteArrayHelper.bytesForShort(ind));
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
        int numberOfKeys = walletHostAPI.getNumberOfKeys();
        HmacHelper.setIsCorrrectKey(false);
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                try {
                    short ind = (short) random.nextInt(numberOfKeys);
                    WalletHostAPI.getTonWalletApi().initiateDeleteOfKey(ByteArrayHelper.bytesForShort(ind));
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
        int numberOfKeys = walletHostAPI.getNumberOfKeys();
        HmacHelper.setIsCorrrectKey(false);
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES - 1; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                try {
                    short ind = (short) random.nextInt(numberOfKeys);
                    WalletHostAPI.getTonWalletApi().initiateDeleteOfKey(ByteArrayHelper.bytesForShort(ind));
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
        walletHostAPI.getNumberOfKeys(); // any other common command can be called
        testNotBlockingAndSuccessfullSigningAfterMacFailing();
    }
}
