package wallet.keychain;

import javacard.framework.Util;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import wallet.tonWalletApi.WalletHostAPI;
import wallet.common.ByteArrayHelper;
import wallet.smartcard.utils.HmacHelper;

import java.util.HashMap;
import java.util.Map;

import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.bSub;
import static wallet.smartcard.WalletAppletConstants.APP_DELETE_KEY_FROM_KEYCHAIN_MODE;
import static wallet.smartcard.WalletAppletConstants.APP_PERSONALIZED;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.SW_INCORRECT_KEY_INDEX;

public class DeleteKeyRecordPositiveTest  extends KeyChainGetTest {
    public static final int NUM_OF_ITER = 10;
    public static final short PACKET_SIZE_FOR_DELETE_KEY_RECORD = (short) 12;
    public static final int DELETE_KEY_RECORD_CORRECT_LC = 64;

    protected Map<String, String> oldAllKeyFromCard = new HashMap<>();
    protected int occupiedSize;
    protected int index;
    protected String mac;
    int lenOfKeyToDelete;

    @Before
    public void before() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        addKeys();
        testKeyMiscData();

        byte state = walletHostAPI.getAppletState();
        assertTrue(state == APP_PERSONALIZED);

        occupiedSize = walletHostAPI.getOccupiedStorageSize();
        oldAllKeyFromCard.clear();
        oldAllKeyFromCard.putAll(walletHostAPI.getKeyChainData());

        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        int ind = random.nextInt(macs.length);
        System.out.println("Hmac index to delete = " + ind);
        System.out.println("\n\n\n Delete key chunk from keystore: ");
        mac = macs[ind];

        lenOfKeyToDelete = walletHostAPI.getKeyChainData().get(mac).length() / 2;
        System.out.println("mac to delete = " + mac);
        System.out.println("key to delete = " + walletHostAPI.getKeyChainData().get(mac));
        System.out.println("key length to delete = " + lenOfKeyToDelete + "\n\n");

        byte[] data = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
        byte[] indexBytes = bSub(data, 0, 2);
        WalletHostAPI.getTonWalletApi().initiateDeleteOfKey(indexBytes);
        index = Util.getShort(data, (short)0);

        assertTrue(index == ind);

        state = walletHostAPI.getAppletState();
        assertTrue(state == APP_DELETE_KEY_FROM_KEYCHAIN_MODE);

        int deleteKeyChunkIsDone = 0;
        while (deleteKeyChunkIsDone == 0) {
            deleteKeyChunkIsDone = WalletHostAPI.getTonWalletApi().deleteKeyChunk();
        }

        byte[] spoiledKey = walletHostAPI.getKeyFromKeyChain(ByteArrayHelper.bytes(mac));
        Assert.assertTrue(!ByteArrayHelper.hex(spoiledKey).equals(walletHostAPI.getKeyChainData().get(mac)));

    }

    @Test
    public void testPositive() throws Exception {
        HmacHelper.setIsCorrrectKey(true);

        int numberOfKeys = walletHostAPI.getNumberOfKeys();
        if (index == (numberOfKeys - 1)) {
            int res = WalletHostAPI.getTonWalletApi().deleteKeyRecord();
            assertTrue(res == 1);
        }
        else {
            int packNum = (short) (numberOfKeys - index - 1) / PACKET_SIZE_FOR_DELETE_KEY_RECORD;
            int tailLen = (short) (numberOfKeys - index - 1) % PACKET_SIZE_FOR_DELETE_KEY_RECORD;
            if (tailLen > 0) packNum++;
            System.out.println("packTotalNum = " + packNum);

            byte[] res = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
            Assert.assertTrue(index == ByteArrayHelper.makeShort(res, 0));

            for (int i = 0; i < packNum - 1; i++) {
                System.out.println("packNum = " + i);
                int deleteKeyRecordIsDone = WalletHostAPI.getTonWalletApi().deleteKeyRecord();
                assertTrue(walletHostAPI.getNumberOfKeys() == walletHostAPI.getKeyChainData().size());
                assertTrue(walletHostAPI.getOccupiedStorageSize() == walletHostAPI.getOccupiedSizeAccordingToKeyChainData());
                assertTrue(deleteKeyRecordIsDone == 0);
                try {
                    WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
                    assertTrue(false);
                } catch (Exception e) {
                    e.printStackTrace();
                    Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_KEY_INDEX)));
                }
            }

            System.out.println("packNum = " + (packNum - 1));
            int deleteKeyRecordIsDone = WalletHostAPI.getTonWalletApi().deleteKeyRecord();
            assertTrue(deleteKeyRecordIsDone == 1);
        }

        walletHostAPI.getKeyChainData().remove(mac);
        walletHostAPI.setOccupiedSizeCounter(walletHostAPI.getOccupiedSizeCounter() - lenOfKeyToDelete);

        byte state = walletHostAPI.getAppletState();
        assertTrue(state == APP_PERSONALIZED);
        assertTrue(!walletHostAPI.getKeyChainData().containsKey(mac));
        assertTrue(oldAllKeyFromCard.keySet().containsAll(walletHostAPI.getKeyChainData().keySet()));
        assertTrue(oldAllKeyFromCard.size() == walletHostAPI.getKeyChainData().size() + 1);
        for(String hmacStr : oldAllKeyFromCard.keySet()) {
            if (hmacStr.equals(mac)) continue;
            assertTrue(oldAllKeyFromCard.get(hmacStr).equals(walletHostAPI.getKeyChainData().get(hmacStr)));
        }
        assertTrue(occupiedSize == walletHostAPI.getOccupiedSizeAccordingToKeyChainData() + oldAllKeyFromCard.get(mac).length()/2);
        assertTrue(occupiedSize == walletHostAPI.getOccupiedSizeCounter() + oldAllKeyFromCard.get(mac).length()/2);
        getAndCheckAllKeysFromKeyChain();
    }
}
