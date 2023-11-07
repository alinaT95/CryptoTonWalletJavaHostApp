package wallet.keychain.negative;

import org.junit.Assert;
import org.junit.Test;
import wallet.tonWalletApi.WalletHostAPI;
import wallet.common.ByteArrayHelper;
import wallet.smartcard.utils.HmacHelper;

import java.util.HashSet;
import java.util.Set;

import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.bConcat;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.WalletAppletConstants.APP_PERSONALIZED;
import static wallet.smartcard.WalletAppletConstants.MAX_HMAC_FAIL_TRIES;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.*;
import static wallet.smartcard.utils.HmacHelper.computeMac;

public class GetKeyIndexInStorageAndLenTest extends KeyChainImmutabilityBaseTest{
    public static final int NUM_OF_ITER = 100;
    public static final int GET_KEY_INDEX_IN_STORAGE_AND_LEN_CORRECT_LC = 96;
    public static final byte GET_KEY_INDEX_IN_STORAGE_AND_LEN_CORRECT_LE = 4;

    @Test
    public void testPositive() throws Exception {
        Set<Integer> indexes = new HashSet<>();
        for(String currentMac: walletHostAPI.getKeyChainData().keySet()){
            byte[] keyMac = ByteArrayHelper.bytes(currentMac);
            byte[] keyIndex = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(keyMac);
            int ind = ByteArrayHelper.makeShort(keyIndex, 0);

            assertTrue((ind >= 0) && (ind < walletHostAPI.getKeyChainData().size()));
            indexes.add(ind);
        }
        assertTrue(indexes.size() == walletHostAPI.getKeyChainData().size());
    }

    @Test
    public void testIncorrectSault() throws Exception {
        byte[] sault = new byte[SAULT_LENGTH];
        byte[] keyMac = new byte[HMAC_SHA_SIG_SIZE];
        for(int i = 0; i < NUM_OF_ITER; i++){
            System.out.println("Iter = " + i);
            try {
                random.nextBytes(sault);
                random.nextBytes(keyMac);
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] dataChunk = bConcat(keyMac, sault);
                WalletHostAPI.getWalletCardReaderWrapper().getIndexAndLenOfKeyInKeyChain(bConcat(dataChunk, computeMac(dataChunk)), GET_KEY_INDEX_IN_STORAGE_AND_LEN_CORRECT_LE);
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
            if(length == GET_KEY_INDEX_IN_STORAGE_AND_LEN_CORRECT_LC) continue;
            byte[] data = new byte[length];
            try {
                random.nextBytes(data);
                System.out.println("data = " + ByteArrayHelper.hex(data));
                WalletHostAPI.getWalletCardReaderWrapper().getIndexAndLenOfKeyInKeyChain(data, GET_KEY_INDEX_IN_STORAGE_AND_LEN_CORRECT_LE);
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
        HmacHelper.setIsCorrrectKey(true);
        for(int le = 0; le <= 255; le++){
            if(le == GET_KEY_INDEX_IN_STORAGE_AND_LEN_CORRECT_LE) continue;
            System.out.println("Le = " + le);
            byte[] sault = walletHostAPI.getSault();
            byte[] keyMac = new byte[HMAC_SHA_SIG_SIZE];
            random.nextBytes(keyMac);
            byte[] mac = computeMac(bConcat(keyMac, sault));
            try {
                WalletHostAPI.getWalletCardReaderWrapper().getHmac(bConcat(keyMac, sault, mac), (byte) le);
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
        byte[] keyMac = new byte[HMAC_SHA_SIG_SIZE];
        random.nextBytes(keyMac);
        try {
            WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(keyMac);
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
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                try {
                    byte[] keyMac = new byte[HMAC_SHA_SIG_SIZE];
                    random.nextBytes(keyMac);
                    WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(keyMac);
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
                    byte[] keyMac = new byte[HMAC_SHA_SIG_SIZE];
                    random.nextBytes(keyMac);
                    WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(keyMac);
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



    //7F00 — run the command for some 32bytes sequence not belonging to fresh hmac array stored by host
    //WalletHostAPI.getWalletCardReaderWrapper().getIndexAndLenOfKeyInKeyChainForTest(wrongData, (byte) 0x04);
    //SW_INCORRECT_KEY_INDEX
    @Test
    public void testNotexistingMac() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        byte[] wrongHmac = new byte[HMAC_SHA_SIG_SIZE];
        random.nextBytes(wrongHmac);
        try {
            WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(wrongHmac);
        }
        catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_KEY_INDEX)));
        }
    }

    @Test
    public void testStabilityAfterInexistingIndex() throws Exception {
        testPositive();
        testNotexistingMac();
        testPositive();
    }

}
