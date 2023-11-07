package wallet.keychain.negative;

import javacard.framework.Util;
import org.junit.After;
import org.junit.Before;
import wallet.tonWalletApi.WalletHostAPI;
import wallet.common.ByteArrayHelper;
import wallet.keychain.KeyChainGetTest;
import wallet.smartcard.utils.HmacHelper;

import java.util.HashMap;
import java.util.Map;

import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.bSub;
import static wallet.smartcard.WalletAppletConstants.APP_DELETE_KEY_FROM_KEYCHAIN_MODE;
import static wallet.smartcard.WalletAppletConstants.APP_PERSONALIZED;

public class DeleteNegativeBase extends KeyChainGetTest {
    protected Map<String, String> oldAllKeyFromCard = new HashMap<>();
    protected int occupiedSize;
    protected int index;
    protected String mac;

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

        int lenOfKeyToDelete = walletHostAPI.getKeyChainData().get(mac).length() / 2;
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
    }

    @After
    public void after() throws Exception {
        byte state = walletHostAPI.getAppletState();
        if (state == APP_DELETE_KEY_FROM_KEYCHAIN_MODE) {
            finishDeleteOperationAndTestKeycahainConsistancy();
        }
    }

    private void finishDeleteOperationAndTestKeycahainConsistancy() throws  Exception {
        HmacHelper.setIsCorrrectKey(true);
        walletHostAPI.deleteKeyFromKeyChainWithoutPresteps(ByteArrayHelper.bytes(mac));
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
