package wallet.keychain;

import org.junit.Test;
import wallet.common.ByteArrayHelper;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static junit.framework.TestCase.assertTrue;

public class KeyChainDeleteLightWeightTest extends KeyChainGetTest {

    private Map<String, String> oldAllKeyFromCard = new HashMap<>();

    @Test
    public void testDeletingOneLargeFromKeyChain() throws Exception {
        walletHostAPI.addLargeKeys();
        testKeyMiscData();
        getAndCheckAllKeysFromKeyChain();

        System.out.println("\n\n Added 3 keys of length 8192 bytes. \n");

        System.out.println("\n\n Start deleting one key with random index: \n");

        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);

        int ind = random.nextInt(macs.length);
        System.out.println("Hmac index = " + ind);
        String hmac = macs[ind];
        walletHostAPI.deleteKeyFromKeyChain(ByteArrayHelper.bytes(hmac));
        getAndCheckAllKeysFromKeyChain();
    }

    @Test
    public void testDeletingAllKeysFromKeyChain() throws Exception {
        walletHostAPI.addKeys10();
        testKeyMiscData();
        getAndCheckAllKeysFromKeyChain();
        System.out.println("\n\n Added 6 keys of length 5000 bytes. \n");

        System.out.println("\n\n Start deleting all keys: \n");

        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        for(int i = 0 ; i < macs.length; i++){
            System.out.println( "\n\n\n ~~~~ Delete Hmac counter = " + i + " ~~~~\n");
            walletHostAPI.deleteKeyFromKeyChain(ByteArrayHelper.bytes(macs[i]));
        }

        testKeyMiscData();
        assertTrue(walletHostAPI.getOccupiedSizeCounter() == 0);
        assertTrue(walletHostAPI.getOccupiedSizeAccordingToKeyChainData() == 0);
        assertTrue(walletHostAPI.getKeyChainData().size() == 0);
    }

    @Test
    public void testDeletingAllKeysOfArbitraryLenFromKeyChain() throws Exception {
        walletHostAPI.addKeys3();
        testKeyMiscData();
        getAndCheckAllKeysFromKeyChain();
        System.out.println("\n\n Added 50 keys of length < 512 bytes. \n");

        System.out.println("\n\n Start deleting all keys: \n");

        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        for(int i = 0 ; i < macs.length; i++){
            System.out.println( "\n\n\n ~~~~ Delete Hmac counter = " + i + " ~~~~\n");
            walletHostAPI.deleteKeyFromKeyChain(ByteArrayHelper.bytes(macs[i]));
        }

        testKeyMiscData();
        assertTrue(walletHostAPI.getOccupiedSizeCounter() == 0);
        assertTrue(walletHostAPI.getOccupiedSizeAccordingToKeyChainData() == 0);
        assertTrue(walletHostAPI.getKeyChainData().size() == 0);
    }

    @Test
    public void testDeletingHalfOfKeysFromKeyChain() throws Exception {
        walletHostAPI.addKeys11();
        testKeyMiscData();
        getAndCheckAllKeysFromKeyChain();
        oldAllKeyFromCard.clear();
        oldAllKeyFromCard.putAll(walletHostAPI.getKeyChainData());

        System.out.println("\n\n Added 10 keys of length 500 bytes. \n");
        System.out.println("\n\n Start deleting the half of keys : \n");

        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        for(int i = 0 ; i < macs.length / 2; i++){
            System.out.println( "\n\n\n ~~~~ Delete Hmac counter = " + i + " ~~~~\n");
            walletHostAPI.deleteKeyFromKeyChain(ByteArrayHelper.bytes(macs[i]));
        }

        for(int i = 0 ; i < macs.length / 2; i++) {
            assertTrue(!walletHostAPI.getKeyChainData().keySet().contains(macs[i]));
        }
        for(int i =  macs.length / 2 ; i < macs.length; i++) {
            assertTrue(walletHostAPI.getKeyChainData().keySet().contains(macs[i]));
        }

        assertTrue(oldAllKeyFromCard.size() == 2 * walletHostAPI.getKeyChainData().size());

        getAndCheckAllKeysFromKeyChain();

    }

    @Test
    public void testDeletingAllKeysExceptOfOneFromKeyChain() throws Exception {
        walletHostAPI.addKeys7();
        testKeyMiscData();
        getAndCheckAllKeysFromKeyChain();

        System.out.println("\n\n Added 1023 keys of length 8 bytes. \n");
        System.out.println("\n\n Start deleting all keys except of one: \n");

        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        int ind = random.nextInt(macs.length);
        System.out.println("Hmac index to leave = " + ind);
        System.out.println("\n\n\n Delete key chunk from keystore: ");
        String mac = macs[ind];

        for(int i = 0 ; i < macs.length; i++){
            if (ind == i) continue;
            System.out.println( "\n\n\n ~~~~ Delete Hmac counter = " + i + " ~~~~\n");
            walletHostAPI.deleteKeyFromKeyChain(ByteArrayHelper.bytes(macs[i]));
        }

        assertTrue(walletHostAPI.getKeyChainData().size() == 1);
        assertTrue(walletHostAPI.getKeyChainData().keySet().contains(mac));

        getAndCheckAllKeysFromKeyChain();

    }
}
