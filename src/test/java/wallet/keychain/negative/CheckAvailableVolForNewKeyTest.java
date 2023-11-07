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

public class CheckAvailableVolForNewKeyTest extends KeyChainImmutabilityBaseTest {
    public static final int CHECK_AVAILABLE_VOL_FOR_NEW_KEY_LC = 66;
    public static final int NUM_OF_ITER = 10;

    @Test
    public void testPositive() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        int freeSize = walletHostAPI.getFreeStorageSize();
        int maxSize = freeSize >  MAX_KEY_SIZE_IN_KEYCHAIN ? MAX_KEY_SIZE_IN_KEYCHAIN : freeSize;
        WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey((short) maxSize);
        for(int i = 0; i < NUM_OF_ITER; i++){
            int size = random.nextInt(maxSize) + 1;
            System.out.println("Size = " + size);
            WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey((short) size);
        }
    }

    @Test
    public void testIncorrectSault() throws Exception {
        byte[] sault = new byte[SAULT_LENGTH];
        int freeSize = walletHostAPI.getFreeStorageSize();
        HmacHelper.setIsCorrrectKey(true);
        for(int i = 0; i < NUM_OF_ITER; i++){
            System.out.println("Iter = " + i);
            try {
                random.nextBytes(sault);
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                int size = random.nextInt(freeSize) + 1;
                byte[] dataChunk = bConcat(new byte[]{(byte)(size >> 8), (byte)(size)}, sault);
                WalletHostAPI.getWalletCardReaderWrapper().checkAvailableVolForNewKey(bConcat(dataChunk, computeMac(dataChunk)));
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_SAULT)));
            }
        }
    }

    @Test
    public void testWrongLength() throws Exception{
        for(int i = 0; i < 255; i++){
            System.out.println("Iter = " + i);
            if(i == CHECK_AVAILABLE_VOL_FOR_NEW_KEY_LC) continue;
            byte[] wrongData = new byte[i];
            try {
                random.nextBytes(wrongData);
                System.out.println("bad data = " + ByteArrayHelper.hex(wrongData));
                WalletHostAPI.getWalletCardReaderWrapper().checkAvailableVolForNewKey(wrongData);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
    }

    @Test
    public void testWrongLengthForKeySize() throws Exception{
        HmacHelper.setIsCorrrectKey(true);
        short size = 0;
        try {
            WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey(size);
            assertTrue(false);
        }
        catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
        }
        size = MAX_KEY_SIZE_IN_KEYCHAIN + 1;
        try {
            WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey(size);
            assertTrue(false);
        }
        catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
        }
    }

    @Test
    public void testOverflow() throws Exception{
        // 7F03 — Run the command with len > free size.
        walletHostAPI.resetKeyChain();
        walletHostAPI.addKeys9();
        saveHmacsBeforeTest();
        int freeSize = walletHostAPI.getFreeStorageSize();
        //int maxSize = freeSize >  MAX_KEY_SIZE_IN_KEYCHAIN ? MAX_KEY_SIZE_IN_KEYCHAIN : freeSize;
        try {
            WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey((short)(freeSize + 1));
            assertTrue(false);
        }
        catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_NOT_ENOUGH_SPACE)));
        }
    }

    @Test
    public void testKeyNumbersExceeded() throws Exception{
        walletHostAPI.resetKeyChain();
        walletHostAPI.addKeys7();
        saveHmacsBeforeTest();
        int freeSize = walletHostAPI.getFreeStorageSize();
        try {
            WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey((short)(freeSize + 1));
            assertTrue(false);
        }
        catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_MAX_KEYS_NUMBER_EXCEEDED)));
        }
    }



    @Test
    public void testOneIncorrectMac() throws Exception{
        int freeSize = walletHostAPI.getFreeStorageSize();
        HmacHelper.setIsCorrrectKey(false);
        try {
            WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey((short) freeSize);
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
        int freeSize = walletHostAPI.getFreeStorageSize();
        HmacHelper.setIsCorrrectKey(false);
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                try {
                    int size = random.nextInt(freeSize)  + 1;
                    WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey((short) size);
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
        int freeSize = walletHostAPI.getFreeStorageSize();
        HmacHelper.setIsCorrrectKey(false);
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES - 1; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                try {
                    int size = random.nextInt(freeSize)  + 1;
                    WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey((short) size);
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
