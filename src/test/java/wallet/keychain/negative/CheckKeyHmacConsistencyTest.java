package wallet.keychain.negative;

import org.junit.After;
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
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.SW_HMAC_VERIFICATION_TRIES_EXPIRED;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.SW_INCORRECT_APDU_HMAC;
import static wallet.smartcard.utils.HmacHelper.computeMac;

public class CheckKeyHmacConsistencyTest extends KeyChainImmutabilityBaseTest {
    public static final int NUM_OF_ITER = 10;
    public static final int CHECK_KEY_HMAC_CONSISTENCY_LC = 96;

    @After
    public void after() throws Exception {
        byte state = walletHostAPI.getAppletState();
        if (state == APP_BLOCKED_MODE) return;
        positiveTest();
    }

    @Test
    public void positiveTest() throws Exception {
        for(String keyMac : walletHostAPI.getAllHmacsOfKeysFromCard().keySet()){
            walletHostAPI.checkKeyHmacConsistency(ByteArrayHelper.bytes(keyMac));
        }
    }

    @Test
    public void testIncorrectSault() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        byte[] sault = new byte[SAULT_LENGTH];
        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        int ind = random.nextInt(macs.length);
        String mac = macs[ind];
        for(int i = 0; i < NUM_OF_ITER; i++){
            System.out.println("Iter = " + i);
            try {
                random.nextBytes(sault);
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] dataChunk = bConcat(ByteArrayHelper.bytes(mac), sault);
                WalletHostAPI.getWalletCardReaderWrapper().checkKeyHmacConsistency(bConcat(dataChunk, computeMac(dataChunk)));
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
            if(length == CHECK_KEY_HMAC_CONSISTENCY_LC) continue;
            byte[] data = new byte[length];
            try {
                random.nextBytes(data);
                System.out.println("data = " + ByteArrayHelper.hex(data));
                WalletHostAPI.getWalletCardReaderWrapper().checkKeyHmacConsistency(data);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
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
            WalletHostAPI.getTonWalletApi().checkKeyHmacConsistency(wrongHmac);
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
        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        int ind = random.nextInt(macs.length);
        String mac = macs[ind];
        try {
            WalletHostAPI.getTonWalletApi().checkKeyHmacConsistency(ByteArrayHelper.bytes(mac));
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
        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        int ind = random.nextInt(macs.length);
        String mac = macs[ind];
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                try {
                    WalletHostAPI.getTonWalletApi().checkKeyHmacConsistency(ByteArrayHelper.bytes(mac));
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
        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        int ind = random.nextInt(macs.length);
        String mac = macs[ind];
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES - 1; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                try {
                    WalletHostAPI.getTonWalletApi().checkKeyHmacConsistency(ByteArrayHelper.bytes(mac));
                    assertTrue(false);
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
}
