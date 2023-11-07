package wallet.testHelper;

import org.junit.Test;
import wallet.common.ByteArrayHelper;
import wallet.tonWalletApi.WalletHostAPI;

import javax.smartcardio.CardException;

import java.util.HashSet;
import java.util.Set;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.hex;
import static wallet.smartcard.WalletAppletConstants.PUBLIC_KEY_LEN;

public class PublicKeyTestStuff {
    public static final int NUM_OF_ITERATIONS = 100;

    private WalletHostAPI walletHostAPI;


    // 0 <= keyIndex <= 2^31 - 1
    private String keyIndex = "1";// "2147483647";

    public PublicKeyTestStuff(WalletHostAPI walletHostAPI) {
        this.walletHostAPI = walletHostAPI;
    }

    public String getKeyIndex() {
        return keyIndex;
    }

    public void testGetPubicKeyForDefaultPath() throws Exception {
        String keyIndex = "0";
        Set<String> pkSet = new HashSet<>();
        for (int i = 0; i < NUM_OF_ITERATIONS; i++) {
            System.out.println("\n Iter = " + i);
            pkSet.add(getPubicKeyForDefaultPath());
            pkSet.add(getPubicKey(keyIndex));
        }
        assertTrue(pkSet.size() == 1);
    }

    public void testGetPubicKey() throws Exception {
        Set<String> pkSet = new HashSet<>();
        for (int i = 0; i < NUM_OF_ITERATIONS; i++) {
            System.out.println("\n Iter = " + i);
            pkSet.add(getPubicKey());
        }
        assertTrue(pkSet.size() == 1);
    }

    public String getPubicKey() throws CardException {
       return getPubicKey(keyIndex);
    }

    public String getPubicKey(String keyIndex) throws CardException {
        byte[] publicKeyBytes = walletHostAPI.getPublicKey(ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex(keyIndex)));

        assertTrue(publicKeyBytes  != null);
        assertTrue(publicKeyBytes.length == PUBLIC_KEY_LEN);
        System.out.println("Public key bytes:");
        System.out.println(hex(publicKeyBytes));
        return ByteArrayHelper.hex(publicKeyBytes);
    }

    public String getPubicKeyForDefaultPath()  throws CardException {
        byte[] publicKeyBytes = walletHostAPI.getPublicKeyWithDefaultHDPath();
        for (int i = 0 ; i < publicKeyBytes.length; i++)
            System.out.println(publicKeyBytes[i]);
        assertTrue(publicKeyBytes  != null);
        assertTrue(publicKeyBytes.length == PUBLIC_KEY_LEN);
        System.out.println("Public key bytes:");
        System.out.println(hex(publicKeyBytes));
        return ByteArrayHelper.hex(publicKeyBytes);
    }
}
