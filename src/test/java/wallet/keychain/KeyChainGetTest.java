package wallet.keychain;

import org.junit.Before;
import org.junit.Test;
import wallet.common.ByteArrayHelper;
import wallet.keychain.KeyChainBaseTest;

import java.util.HashSet;
import java.util.Set;

import static junit.framework.TestCase.assertTrue;
import static wallet.smartcard.WalletAppletConstants.APP_WAITE_AUTHORIZATION_MODE;

public class KeyChainGetTest extends KeyChainBaseTest {
    public static final int NUM_OF_ITER = 10;

    @Test
    public void testMultipleGettingAllKeysFromKeyChain() throws Exception {
        System.out.println("\n\n Get all keys multiple times testHelper: \n");
        for (int i = 0; i < NUM_OF_ITER; i++) {
            System.out.println("\n\n\n --------- Test iter = " + i + " ---------\n ");
            testGettingAllKeysFromKeyChain();
        }
    }

    @Test
    public void testGettingAllKeysFromKeyChain() throws Exception {
        walletHostAPI.addKeys4();
        getAndCheckAllKeysFromKeyChain();
    }


    @Test
    public void testGettingRandomKeysFromKeyChain() throws Exception {
        walletHostAPI.addKeys4();
        testKeyMiscData();
        System.out.println("\n\n Get random keys testHelper: \n");
        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        for (int i = 0; i < NUM_OF_ITER; i++) {
            System.out.println("\n\n\n --------- Test iter = " + i + " ---------\n ");
            int ind = random.nextInt(macs.length);
            System.out.println("Hmac index = " + ind);
            String hmac = macs[ind];
            getKeyFromKeyChain(hmac);
        }
        testKeyMiscData();
    }

    @Test
    public void testGettingRandomLargeKeyFromKeyChain() throws Exception {
        walletHostAPI.addLargeKeys();
        testKeyMiscData();
        System.out.println("\n\n Get random keys testHelper: \n");
        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        int ind = random.nextInt(macs.length);
        System.out.println("Hmac index = " + ind);
        String hmac = macs[ind];
        getKeyFromKeyChain(hmac);
        testKeyMiscData();
    }


    protected void getAndCheckAllKeysFromKeyChain() throws Exception {
        System.out.println("\n\n Get all keys testHelper: \n");
        testKeyMiscData();
        int counter = 0;
        for(String hmac : walletHostAPI.getKeyChainData().keySet()){
            System.out.println( "\n\n\n ~~~~ Get Hmac counter = " + counter + " ~~~~\n");
            getKeyFromKeyChain(hmac);
            counter++;
        }
        testKeyMiscData();
    }

    private void getKeyFromKeyChain(String hmac) throws Exception{
        assertTrue(walletHostAPI.getKeyChainData().keySet().contains(hmac));
        String key = walletHostAPI.getKeyChainData().get(hmac);
        byte[] keyFromCard = walletHostAPI.getKeyFromKeyChain(ByteArrayHelper.bytes(hmac));
        assertTrue(key.equals(ByteArrayHelper.hex(keyFromCard)));
    }
}
