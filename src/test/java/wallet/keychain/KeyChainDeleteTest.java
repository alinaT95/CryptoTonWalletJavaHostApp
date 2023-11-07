package wallet.keychain;

import org.junit.Test;
import wallet.common.ByteArrayHelper;

import java.util.HashMap;
import java.util.Map;

import static junit.framework.TestCase.assertTrue;

public class KeyChainDeleteTest extends KeyChainGetTest {
    public static final int NUM_OF_ITER = 10;

    private Map<String, String> oldAllKeyFromCard = new HashMap<>();

    @Test
    public void testMultipleDeletingAllKeysFromKeyChain() throws Exception {
        System.out.println("\n\n Start deleting all keys multiple times testHelper: \n");
        for(int i = 0; i < NUM_OF_ITER; i++) {
            System.out.println("\n\n\n --------- Test iter = " + i + " ---------\n ");
            testDeletingAllKeysFromKeyChain();
        }
    }


    @Test
    public void testDeletingAllKeysFromKeyChain() throws Exception {
        addKeys();
        testKeyMiscData();
        System.out.println("\n\n Start deleting all keys testHelper: \n");

        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        for(int i = 0 ; i < macs.length; i++){
            System.out.println( "\n\n\n ~~~~ Delete Hmac counter = " + i + " ~~~~\n");
            deleteKeyFromKeyChain(macs[i]);
        }

        testKeyMiscData();
        assertTrue(walletHostAPI.getOccupiedSizeCounter() == 0);
        assertTrue(walletHostAPI.getOccupiedSizeAccordingToKeyChainData() == 0);
        assertTrue(walletHostAPI.getKeyChainData().size() == 0);
    }

    @Test
    public void testMultipleDeletingAllRandomKeyFromKeyChain() throws Exception {
        System.out.println("\n\n Start deleting all keys randomly multiple times testHelper: \n");
        for(int i = 0; i < NUM_OF_ITER; i++) {
            System.out.println("\n\n\n --------- Test iter = " + i + " ---------\n ");
            testDeletingAllKeysFromKeyChainRandomly();
        }
    }

    @Test
    public void testDeletingAllKeysFromKeyChainRandomly() throws Exception {
        addKeys();
        testKeyMiscData();

        System.out.println("\n\n Start deleting all keys randomly testHelper: \n");
        int counter = 0;
        while (walletHostAPI.getKeyChainData().size() > 0) {
            String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
            int ind = random.nextInt(macs.length);
            System.out.println( "\n\n\n ~~~~ Delete Hmac counter = " + counter + " ~~~~\n");
            System.out.println("Hmac index to delete = " + ind);
            deleteKeyFromKeyChain(macs[ind]);
            counter++;
        }

        testKeyMiscData();
        assertTrue(walletHostAPI.getOccupiedSizeCounter() == 0);
        assertTrue(walletHostAPI.getOccupiedSizeAccordingToKeyChainData() == 0);
        assertTrue(walletHostAPI.getKeyChainData().size() == 0);
    }

    @Test
    public void testDeletingRandomKeyFromKeyChain() throws Exception {
        addKeys();
        testKeyMiscData();

        System.out.println("\n\n Start deleting one random key testHelper: \n");
        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        int ind = random.nextInt(macs.length);
        System.out.println("Hmac index to delete = " + ind);
        deleteKeyFromKeyChain(macs[ind]);

        testKeyMiscData();
    }


    private void deleteKeyFromKeyChain(String hmac) throws Exception {
        getAndCheckAllKeysFromKeyChain();

        int occupiedSizeOld = walletHostAPI.getOccupiedSizeAccordingToKeyChainData();
        oldAllKeyFromCard.clear();
        oldAllKeyFromCard.putAll(walletHostAPI.getKeyChainData());
        assertTrue(oldAllKeyFromCard.containsKey(hmac));

        walletHostAPI.deleteKeyFromKeyChain(ByteArrayHelper.bytes(hmac));

        assertTrue(!walletHostAPI.getKeyChainData().containsKey(hmac));
        assertTrue(oldAllKeyFromCard.keySet().containsAll(walletHostAPI.getKeyChainData().keySet()));
        assertTrue(oldAllKeyFromCard.size() == walletHostAPI.getKeyChainData().size() + 1);
        for(String hmacStr : oldAllKeyFromCard.keySet()) {
            if (hmacStr.equals(hmac)) continue;
            assertTrue(oldAllKeyFromCard.get(hmacStr).equals(walletHostAPI.getKeyChainData().get(hmacStr)));
        }

        assertTrue(occupiedSizeOld == walletHostAPI.getOccupiedSizeAccordingToKeyChainData() + oldAllKeyFromCard.get(hmac).length()/2);
        assertTrue(occupiedSizeOld == walletHostAPI.getOccupiedSizeCounter() + oldAllKeyFromCard.get(hmac).length()/2);

        getAndCheckAllKeysFromKeyChain();
    }
}
