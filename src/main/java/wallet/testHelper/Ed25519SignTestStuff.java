package wallet.testHelper;

import org.junit.Test;
import wallet.common.ByteArrayHelper;
import wallet.tonWalletApi.WalletHostAPI;

import java.util.Random;

import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.hex;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.WalletAppletConstants.DATA_FOR_SIGNING_MAX_SIZE_FOR_CASE_WITH_PATH;

public class Ed25519SignTestStuff {
    public static final int NUM_OF_ITERATIONS = 100;
    public static Random random = new Random();

    private WalletHostAPI walletHostAPI;

    private Ed25519SigVerificator verificator = new Ed25519SigVerificator();

    public Ed25519SignTestStuff(WalletHostAPI walletHostAPI) {
        this.walletHostAPI = walletHostAPI;
    }

    public void testSignShortForLen32ForRandomHdIndexes() throws Exception {
        byte[] data = new byte[TRANSACTION_HASH_SIZE]; //new byte[DATA_FOR_SIGNING_MIN_LEN];//new byte[DATA_FOR_SIGNING_MAX_SIZE_FOR_CASE_WITH_PATH];//
        for (int i = 0; i < NUM_OF_ITERATIONS; i++) {
            int ind = random.nextInt(Integer.MAX_VALUE);
            System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            System.out.println("hdIndex = " + ind);
            System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~n\n\n");
            random.nextBytes(data);
            signShortAndVerifySignature(Integer.toString(ind), data);
        }
    }

    public void testSignShortForAllLengthForRandomHdIndexes() throws Exception {
        for(int len = DATA_FOR_SIGNING_MIN_LEN; len <= DATA_FOR_SIGNING_MAX_SIZE_FOR_CASE_WITH_PATH ; len++){
            int ind = random.nextInt(Integer.MAX_VALUE);
            System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            System.out.println("hdIndex = " + ind);
            System.out.println("len = " + len);
            System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
            byte[] data = new byte[len];
            random.nextBytes(data);
            signShortAndVerifySignature(Integer.toString(ind), data);
        }
    }


    public void testSignWithDefaultPathForGivenDataLength(int len, String hdIndex) throws Exception {
        System.out.println("TEST for Data length = " + len);
        byte[] data = new byte[len];
        for (int i = 0; i < NUM_OF_ITERATIONS; i++) {
            System.out.println("number of iteration = " + i);
            random.nextBytes(data);
            signShortAndVerifySignature(hdIndex, data);
        }
    }

    public void signShortAndVerifySignature(String hdIndex, byte[] data)  throws Exception {
        byte[] signatureBytes  = signShort(hdIndex, data);
        verifySignature(hdIndex, data, signatureBytes);
    }

    public byte[] signShort(String hdIndex, byte[] data)  throws Exception {
       // appletStateChecker.checkPersonalizedState();
        if (data == null || data.length == 0) throw new Exception("Data is empty!");

        walletHostAPI.verifyPin(PIN);

        System.out.println("Data for signing = " + hex(data));

        byte[] signatureBytes = walletHostAPI.signShortMessage(data, hdIndex);
        System.out.println("signatureBytes = " + hex(signatureBytes));

        assertTrue(signatureBytes  != null);
        assertTrue(signatureBytes.length == SIG_LEN);
        return signatureBytes;
    }

    public void verifySignature(String hdIndex, byte[] data, byte[] signatureBytes)  throws Exception {
     //   appletStateChecker.checkPersonalizedState();
        System.out.println("from verify Data = " + hex(data));
        System.out.println("from verify SignatureBytes = " + hex(signatureBytes));

        byte[] publicKeyBytesFromCard = walletHostAPI.getPublicKey(ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex(hdIndex)));
        System.out.println("from verify PK = " + hex(publicKeyBytesFromCard));

        verificator.setPublicKey(publicKeyBytesFromCard);
        boolean res =  verificator.verify(data, signatureBytes);

        System.out.println("Verify result = " + res);

        assertTrue(res);
    }
}
