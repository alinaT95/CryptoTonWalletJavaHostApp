package wallet.keychain;

import org.junit.Test;
import wallet.tonWalletApi.WalletHostAPI;
import wallet.common.ByteArrayHelper;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;

public class TimingTest extends KeyChainGetTest {
    @Test
    public void testDeletingRandomKeyFromKeyChain() throws Exception {
        walletHostAPI.addKeys0();
        //testKeyMiscData();
        System.out.println("num of keys = " + walletHostAPI.getNumberOfKeys());

        System.out.println("\n\n Start deleting one random key testHelper: \n");
        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        int ind = 0; //random.nextInt(macs.length);
        System.out.println("Hmac index to delete = " + ind);
        System.out.println(macs[ind]);

        byte[] data = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(macs[ind]));
        assertEquals(ind, ByteArrayHelper.makeShort(data, 0));

        long start = System.currentTimeMillis();
        walletHostAPI.deleteKeyFromKeyChain(ByteArrayHelper.bytes(macs[ind]));
        long end = System.currentTimeMillis();
        long time = (end - start) / 1000;
        System.out.println("time = " + time);
      //  testKeyMiscData();
    }

    @Test
    public void testChangingRandomKeyFromKeyChain() throws Exception {
        walletHostAPI.addKeys0();
        //testKeyMiscData();
        System.out.println("num of keys = " + walletHostAPI.getNumberOfKeys());

        System.out.println("\n\n Start changing one random key testHelper: \n");
        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        int ind = random.nextInt(macs.length);
        System.out.println("Hmac index to change = " + ind);
        System.out.println(macs[ind]);

        int len = walletHostAPI.getKeyChainData().get(macs[ind]).length() / 2;
        byte[] newKey = new byte[len];
        random.nextBytes(newKey);

        long start = System.currentTimeMillis();
        walletHostAPI.changeKeyInKeyChain(newKey, ByteArrayHelper.bytes(macs[ind]));
        walletHostAPI.deleteKeyFromKeyChain(ByteArrayHelper.bytes(macs[ind]));
        long end = System.currentTimeMillis();
        long time = (end - start) / 1000;
        System.out.println("time = " + time);
        //  testKeyMiscData();
    }

    @Test
    public void testAddRandomKeyFromKeyChain() throws Exception {
        walletHostAPI.resetKeyChain();
        int size = 8192;
        int numOfKeysForAdding = 3;
        byte[] key = new byte[size];
        for (int i = 0; i < numOfKeysForAdding; i++) {
            random.nextBytes(key);
            System.out.println("\n \n Iteration = " + i);
            long start = System.currentTimeMillis();
            walletHostAPI.addKeyIntoKeyChain(key);
            long end = System.currentTimeMillis();
            long time = (end - start) / 1000;
            System.out.println("time = " + time);
        }
    }

}
