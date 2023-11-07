package wallet.keychain;

import org.junit.Test;
import wallet.common.ByteArrayHelper;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertTrue;
import static wallet.smartcard.utils.HmacHelper.computeMac;

public class KeyChainChangeTest extends KeyChainGetTest {
    public static final int NUM_OF_ITER = 10;

    private Map<String, String> oldAllKeyFromCard = new HashMap<>();

    @Test
    public void testMultipleChangingAllKeysFromKeyChain() throws Exception {
        System.out.println("\n\n Start changing all keys multiple times testHelper: \n");
        for(int i = 0; i < NUM_OF_ITER; i++) {
            System.out.println("\n\n\n --------- Test iter = " + i + " ---------\n ");
            testChangingAllKeysFromKeyChain();
        }
    }

    @Test
    public void testChangingAllKeysFromKeyChain() throws Exception {
        addKeys();
        testKeyMiscData();
        System.out.println("\n\n Start changing all keys testHelper: \n");
        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        for(int i = 0 ; i < macs.length; i++){
            System.out.println( "\n\n\n ~~~~ Change Hmac counter = " + i + " ~~~~\n");
            changeKeyFromKeyChain(macs[i]);
        }
        testKeyMiscData();
    }


    @Test
    public void testMultipleChangingRandomKeysFromKeyChain() throws Exception {
        addKeys();
        testKeyMiscData();
        System.out.println("\n\n Start changing multiple random keys testHelper: \n");
        for(int i = 0; i < NUM_OF_ITER; i++){
            String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
            int ind = random.nextInt(macs.length);
            System.out.println("\n\n\n --------- Test iter = " + i + " ---------\n ");
            System.out.println("Hmac index to change = " + ind);
            changeKeyFromKeyChain(macs[ind]);
        }
        testKeyMiscData();
    }

    @Test
    public void testChangingRandomKeyFromKeyChain() throws Exception {
        addKeys();
        testKeyMiscData();
        System.out.println("\n\n Start changing one random key testHelper: \n");
        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        int ind = random.nextInt(macs.length);
        System.out.println("Hmac index to change = " + ind);
        changeKeyFromKeyChain(macs[ind]);
        testKeyMiscData();
    }

    private void changeKeyFromKeyChain(String hmac) throws Exception {
        getAndCheckAllKeysFromKeyChain();

        int occupiedSizeOld = walletHostAPI.getOccupiedSizeAccordingToKeyChainData();
        oldAllKeyFromCard.clear();
        oldAllKeyFromCard.putAll(walletHostAPI.getKeyChainData());
        assertTrue(oldAllKeyFromCard.keySet().contains(hmac));

        int lenOfKey = walletHostAPI.getKeyChainData().get(hmac).length() / 2;
        byte[] newKey = new byte[lenOfKey];
        random.nextBytes(newKey);
        byte[] newMac = computeMac(newKey);

        walletHostAPI.changeKeyInKeyChain(newKey, ByteArrayHelper.bytes(hmac));

        assertTrue(!walletHostAPI.getKeyChainData().containsKey(hmac));
        assertTrue(walletHostAPI.getKeyChainData().containsKey(ByteArrayHelper.hex(newMac)));
        assertTrue(!oldAllKeyFromCard.keySet().contains(ByteArrayHelper.hex(newMac)));
        assertTrue(oldAllKeyFromCard.size() == walletHostAPI.getKeyChainData().size());

        for(String hmacStr : oldAllKeyFromCard.keySet()) {
            if (hmacStr.equals(hmac)) continue;
            assertTrue(walletHostAPI.getKeyChainData().keySet().contains(hmacStr));
            assertTrue(walletHostAPI.getKeyChainData().get(hmacStr).equals(oldAllKeyFromCard.get(hmacStr)));
        }

        String newHmac  = ByteArrayHelper.hex(newMac);
        for(String hmacStr : walletHostAPI.getKeyChainData().keySet()) {
            if (hmacStr.equals(newHmac)) continue;
            assertTrue(oldAllKeyFromCard.keySet().contains(hmacStr));
            assertTrue(oldAllKeyFromCard.get(hmacStr).equals(walletHostAPI.getKeyChainData().get(hmacStr)));
        }

        assertTrue(occupiedSizeOld == walletHostAPI.getOccupiedSizeAccordingToKeyChainData());
        assertTrue(occupiedSizeOld == walletHostAPI.getOccupiedSizeCounter());

        getAndCheckAllKeysFromKeyChain();
    }
}
