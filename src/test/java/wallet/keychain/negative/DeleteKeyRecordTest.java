package wallet.keychain.negative;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import wallet.tonWalletApi.WalletHostAPI;
import wallet.common.ByteArrayHelper;
import wallet.smartcard.utils.HmacHelper;

import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.bConcat;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.*;
import static wallet.smartcard.utils.HmacHelper.computeMac;

public class DeleteKeyRecordTest extends DeleteNegativeBase  {
    public static final int NUM_OF_ITER = 10;
    public static final int DELETE_KEY_RECORD_CORRECT_LC = 64;

    @Before
    public void beforeForDeleteKeyRecord() throws Exception {
        byte state = walletHostAPI.getAppletState();
        assertTrue(state == APP_DELETE_KEY_FROM_KEYCHAIN_MODE);

        int deleteKeyChunkIsDone = 0;
        while (deleteKeyChunkIsDone == 0) {
            deleteKeyChunkIsDone = WalletHostAPI.getTonWalletApi().deleteKeyChunk();
        }

        byte[] spoiledKey = walletHostAPI.getKeyFromKeyChain(ByteArrayHelper.bytes(mac));
        Assert.assertTrue(!ByteArrayHelper.hex(spoiledKey).equals(walletHostAPI.getKeyChainData().get(mac)));
    }

    @After
    public void afterForDeleteKeyRecord() throws  Exception{
        byte state = walletHostAPI.getAppletState();
        if (state == APP_DELETE_KEY_FROM_KEYCHAIN_MODE) {
            byte[] res = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
            Assert.assertTrue(index == ByteArrayHelper.makeShort(res, 0));
            Assert.assertTrue(occupiedSize == walletHostAPI.getOccupiedStorageSize());
            Assert.assertTrue(oldAllKeyFromCard.size() == walletHostAPI.getKeyChainData().size());
            Assert.assertTrue(oldAllKeyFromCard.keySet().containsAll(walletHostAPI.getKeyChainData().keySet()));
            Assert.assertTrue(walletHostAPI.getKeyChainData().keySet().containsAll(oldAllKeyFromCard.keySet()));
            testKeyMiscData();
        }
    }

    @Test
    public void testIncorrectSault() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        byte[] sault = new byte[SAULT_LENGTH];
        for(int i = 0; i < NUM_OF_ITER; i++){
            System.out.println("Iter = " + i);
            try {
                random.nextBytes(sault);
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                WalletHostAPI.getWalletCardReaderWrapper().deleteKeyRecord(bConcat(sault, computeMac(sault)), DELETE_KEY_RECORD_LE);
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
            if(length == DELETE_KEY_RECORD_CORRECT_LC) continue;
            byte[] data = new byte[length];
            try {
                random.nextBytes(data);
                System.out.println("data = " + ByteArrayHelper.hex(data));
                WalletHostAPI.getWalletCardReaderWrapper().deleteKeyRecord(data, DELETE_KEY_CHUNK_LE);
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
            if(le == DELETE_KEY_CHUNK_LE) continue;
            System.out.println("Le = " + le);
            byte[] sault = walletHostAPI.getSault();
            try {
                WalletHostAPI.getWalletCardReaderWrapper().deleteKeyRecord(bConcat(sault, computeMac(sault)), (byte) le);
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
        try {
            WalletHostAPI.getTonWalletApi().deleteKeyRecord();
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
            if (state == APP_DELETE_KEY_FROM_KEYCHAIN_MODE) {
                try {
                    WalletHostAPI.getTonWalletApi().deleteKeyChunk();
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
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES - 1; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_DELETE_KEY_FROM_KEYCHAIN_MODE) {
                try {
                    WalletHostAPI.getTonWalletApi().deleteKeyRecord();
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
