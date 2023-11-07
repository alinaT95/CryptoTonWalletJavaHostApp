package wallet.keychain;

import org.junit.Test;
import wallet.common.ByteArrayHelper;

import java.util.*;

import static junit.framework.TestCase.assertTrue;
import static wallet.smartcard.utils.HmacHelper.computeMac;

public class KeyChainChangeLightWeightTest extends KeyChainGetTest {
    private Map<String, String> oldAllKeyFromCard = new HashMap<>();


    @Test
    public void testChangingHalfOfKeysFromKeyChain() throws Exception {
        addKeys();
        testKeyMiscData();
        getAndCheckAllKeysFromKeyChain();

        System.out.println("\n\n Start changing half of  keys testHelper: \n");

        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);

        int occupiedSizeOld = walletHostAPI.getOccupiedSizeAccordingToKeyChainData();
        oldAllKeyFromCard.clear();
        oldAllKeyFromCard.putAll(walletHostAPI.getKeyChainData());

        List<String> newMacs = new ArrayList<>();
        for(int i = 0 ; i < macs.length / 2; i++){
            System.out.println( "\n\n\n ~~~~ Change Hmac counter = " + i + " ~~~~\n");
            int lenOfKey = walletHostAPI.getKeyChainData().get(macs[i]).length() / 2;
            byte[] newKey = new byte[lenOfKey];
            random.nextBytes(newKey);
            byte[] newMac = computeMac(newKey);
            walletHostAPI.changeKeyInKeyChain(newKey, ByteArrayHelper.bytes(macs[i]));
            newMacs.add(ByteArrayHelper.hex(newMac));
        }

        assertTrue(occupiedSizeOld == walletHostAPI.getOccupiedSizeAccordingToKeyChainData());
        assertTrue(occupiedSizeOld == walletHostAPI.getOccupiedSizeCounter());
        assertTrue(oldAllKeyFromCard.size() == walletHostAPI.getKeyChainData().size());
        assertTrue(walletHostAPI.getKeyChainData().keySet().containsAll(newMacs));
        for(int i =  macs.length / 2 ; i < macs.length; i++) {
            assertTrue(walletHostAPI.getKeyChainData().keySet().contains(macs[i]));
        }

        getAndCheckAllKeysFromKeyChain();
    }

    @Test
    public void testChangingAllKeysExceptOfOneFromKeyChain() throws Exception {
        //addKeys();
        walletHostAPI.addLargeKeys();
        testKeyMiscData();
        getAndCheckAllKeysFromKeyChain();

        System.out.println("\n\n Start changing all keys except of one testHelper: \n");

        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        int ind = random.nextInt(macs.length);
        System.out.println("Hmac index to leave = " + ind);
        System.out.println("\n\n\n Delete key chunk from keystore: ");
        String mac = macs[ind];

        int occupiedSizeOld = walletHostAPI.getOccupiedSizeAccordingToKeyChainData();
        oldAllKeyFromCard.clear();
        oldAllKeyFromCard.putAll(walletHostAPI.getKeyChainData());
        assertTrue(oldAllKeyFromCard.keySet().contains(mac));


        List<String> newMacs = new ArrayList<>();
        for(int i = 0 ; i < macs.length; i++){
            if (ind == i) continue;
            System.out.println( "\n\n\n ~~~~ Change Hmac counter = " + i + " ~~~~\n");
            int lenOfKey = walletHostAPI.getKeyChainData().get(macs[i]).length() / 2;
            byte[] newKey = new byte[lenOfKey];
            random.nextBytes(newKey);
            byte[] newMac = computeMac(newKey);
            walletHostAPI.changeKeyInKeyChain(newKey, ByteArrayHelper.bytes(macs[i]));
            newMacs.add(ByteArrayHelper.hex(newMac));
        }

        assertTrue(occupiedSizeOld == walletHostAPI.getOccupiedSizeAccordingToKeyChainData());
        assertTrue(occupiedSizeOld == walletHostAPI.getOccupiedSizeCounter());
        assertTrue(oldAllKeyFromCard.size() == walletHostAPI.getKeyChainData().size());
        assertTrue(walletHostAPI.getKeyChainData().keySet().contains(mac));
        assertTrue(walletHostAPI.getKeyChainData().keySet().containsAll(newMacs));

        Set<String> intersection = new LinkedHashSet<String>(walletHostAPI.getKeyChainData().keySet()); // use the copy constructor
        intersection.retainAll(oldAllKeyFromCard.keySet());
        assertTrue(intersection.size() == 1);
        assertTrue(intersection.contains(mac));

        getAndCheckAllKeysFromKeyChain();
    }

}
