package wallet.keychain.negative;

import org.junit.Assert;
import org.junit.Test;
import wallet.tonWalletApi.WalletHostAPI;
import wallet.common.ByteArrayHelper;
import wallet.smartcard.utils.HmacHelper;

import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.bConcat;
import static wallet.common.ByteArrayHelper.bSub;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.*;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.SW_INCORRECT_APDU_HMAC;
import static wallet.smartcard.utils.HmacHelper.computeMac;

public class DeleteKeyChunkTest extends DeleteNegativeBase {
    public static final int NUM_OF_ITER = 10;
    public static final short PACKET_SIZE_FOR_DELETE_KEY_CHUNK = (short) 128;
    public static final int DELETE_KEY_CHUNK_CORRECT_LC = 64;


    @Test
    public void testPositive() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        int numberOfKeys = walletHostAPI.getNumberOfKeys();
        if (index == (numberOfKeys - 1)) {
            int res = WalletHostAPI.getTonWalletApi().deleteKeyChunk();
            assertTrue(res == 1);
        }
        else {
            int offsetOfNextKey = walletHostAPI.getKeyChainData().entrySet().stream().limit(index + 1).mapToInt(entry -> entry.getValue().length() / 2).sum();
            int packNum = (short)(occupiedSize - offsetOfNextKey) / PACKET_SIZE_FOR_DELETE_KEY_CHUNK;
            int tailLen = (short)(occupiedSize - offsetOfNextKey) % PACKET_SIZE_FOR_DELETE_KEY_CHUNK;
            if (tailLen > 0) packNum++;
            System.out.println("packTotalNum = " + packNum);

            byte[] notSpoiledKey = walletHostAPI.getKeyFromKeyChain(ByteArrayHelper.bytes(mac));
            Assert.assertTrue(ByteArrayHelper.hex(notSpoiledKey).equals(walletHostAPI.getKeyChainData().get(mac)));

            for(int i = 0; i < packNum - 1; i++){
                System.out.println("packNum = " + i);
                int deleteKeyChunkIsDone = WalletHostAPI.getTonWalletApi().deleteKeyChunk();
                byte[] spoiledKey = walletHostAPI.getKeyFromKeyChain(ByteArrayHelper.bytes(mac));
                Assert.assertTrue(!ByteArrayHelper.hex(spoiledKey).equals(walletHostAPI.getKeyChainData().get(mac)));
                assertTrue(deleteKeyChunkIsDone == 0);
            }

            System.out.println("packNum = " + (packNum - 1));
            int deleteKeyChunkIsDone = WalletHostAPI.getTonWalletApi().deleteKeyChunk();
            assertTrue(deleteKeyChunkIsDone == 1);
        }

        Assert.assertTrue(occupiedSize == walletHostAPI.getOccupiedStorageSize());
        Assert.assertTrue(oldAllKeyFromCard.size() == walletHostAPI.getKeyChainData().size());
        Assert.assertTrue(oldAllKeyFromCard.keySet().containsAll(walletHostAPI.getKeyChainData().keySet()));
        Assert.assertTrue(walletHostAPI.getKeyChainData().keySet().containsAll(oldAllKeyFromCard.keySet()));
        testKeyMiscData();

        byte[] spoiledKey = walletHostAPI.getKeyFromKeyChain(ByteArrayHelper.bytes(mac));
        Assert.assertTrue(!ByteArrayHelper.hex(spoiledKey).equals(walletHostAPI.getKeyChainData().get(mac)));

        byte state = walletHostAPI.getAppletState();
        assertTrue(state == APP_DELETE_KEY_FROM_KEYCHAIN_MODE);
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
                WalletHostAPI.getWalletCardReaderWrapper().deleteKeyChunk(bConcat(sault, computeMac(sault)), DELETE_KEY_CHUNK_LE);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_SAULT)));
                byte[] notSpoiledKey = walletHostAPI.getKeyFromKeyChain(ByteArrayHelper.bytes(mac));
                Assert.assertTrue(ByteArrayHelper.hex(notSpoiledKey).equals(walletHostAPI.getKeyChainData().get(mac)));
            }
        }
    }

    @Test
    public void testWrongLengthLc() throws Exception {
        for(int length = 0; length <= 255; length++){
            System.out.println("Length = " + length);
            if(length == DELETE_KEY_CHUNK_CORRECT_LC) continue;
            byte[] data = new byte[length];
            try {
                random.nextBytes(data);
                System.out.println("data = " + ByteArrayHelper.hex(data));
                WalletHostAPI.getWalletCardReaderWrapper().deleteKeyChunk(data, DELETE_KEY_CHUNK_LE);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
                byte[] notSpoiledKey = walletHostAPI.getKeyFromKeyChain(ByteArrayHelper.bytes(mac));
                Assert.assertTrue(ByteArrayHelper.hex(notSpoiledKey).equals(walletHostAPI.getKeyChainData().get(mac)));
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
                WalletHostAPI.getWalletCardReaderWrapper().deleteKeyChunk(bConcat(sault, computeMac(sault)), (byte) le);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
                byte[] notSpoiledKey = walletHostAPI.getKeyFromKeyChain(ByteArrayHelper.bytes(mac));
                Assert.assertTrue(ByteArrayHelper.hex(notSpoiledKey).equals(walletHostAPI.getKeyChainData().get(mac)));
            }
        }
    }

    @Test
    public void testOneIncorrectMac() throws Exception{
        HmacHelper.setIsCorrrectKey(false);
        try {
            WalletHostAPI.getTonWalletApi().deleteKeyChunk();
            assertTrue(false);
        }
        catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_APDU_HMAC)));
            HmacHelper.setIsCorrrectKey(true);
            byte[] notSpoiledKey = walletHostAPI.getKeyFromKeyChain(ByteArrayHelper.bytes(mac));
            Assert.assertTrue(ByteArrayHelper.hex(notSpoiledKey).equals(walletHostAPI.getKeyChainData().get(mac)));
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
                    WalletHostAPI.getTonWalletApi().deleteKeyChunk();
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
