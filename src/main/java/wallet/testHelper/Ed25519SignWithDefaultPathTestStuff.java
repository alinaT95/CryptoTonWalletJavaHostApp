package wallet.testHelper;

import wallet.common.ByteArrayHelper;
import wallet.tonWalletApi.WalletHostAPI;

import java.util.Random;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.hex;
import static wallet.smartcard.WalletAppletConstants.PIN;
import static wallet.smartcard.WalletAppletConstants.SIG_LEN;

public class Ed25519SignWithDefaultPathTestStuff {
    public static final int NUM_OF_ITERATIONS = 100;
    public static Random random = new Random();

    private WalletHostAPI walletHostAPI;

    private Ed25519SigVerificator verificator = new Ed25519SigVerificator();

    public Ed25519SignWithDefaultPathTestStuff(WalletHostAPI walletHostAPI) {
        this.walletHostAPI = walletHostAPI;
    }

    public void testSignWithDefaultPathForGivenDataLength(int len) throws Exception {
        System.out.println("TEST for Data length = " + len);
        byte[] data = new byte[len];
        for (int i = 0; i < NUM_OF_ITERATIONS; i++) {
            System.out.println("number of iteration = " + i);
            signShortWithDefaultPathAndVerifySignature(data);
        }
    }

    public void testSignWithDefaultPathVsSignShortForGivenDataLength(int len) throws Exception {
        System.out.println("TEST for Data length = " + len);
        byte[] data = new byte[len];
        for (int i = 0; i < NUM_OF_ITERATIONS; i++) {
            System.out.println("number of iteration = " + i);
            signShortWithDefaultPathVsSignShort(data);
        }
    }

    public byte[] signShortWithDefaultPathVsSignShort(byte[] data)  throws Exception {
        if (data == null || data.length == 0) throw new Exception("Data is empty!");

        walletHostAPI.verifyPin(PIN);

        random.nextBytes(data);
        System.out.println("Data for signing = " + hex(data));

        byte[] signatureBytesForDefaultPath = walletHostAPI.signShortMessageWithDefaultPath(data);
        System.out.println("signatureBytesForDefaultPath = " + hex(signatureBytesForDefaultPath));

        walletHostAPI.verifyPin(PIN);

        byte[] signatureBytes = walletHostAPI.signShortMessage(data, "0");
        System.out.println("signatureBytes = " + hex(signatureBytes));

        assertEquals(ByteArrayHelper.hex(signatureBytes), ByteArrayHelper.hex(signatureBytesForDefaultPath));

        assertTrue(signatureBytes  != null);
        assertTrue(signatureBytes.length == SIG_LEN);
        return signatureBytes;
    }


    public void signShortWithDefaultPathAndVerifySignature(byte[] data)  throws Exception {
        byte[] signatureBytes = signShortWithDefaultPath(data);
        verifySignatureWithDefaultPath(data, signatureBytes);
    }

    public byte[] signShortWithDefaultPath(byte[] data)  throws Exception {
        if (data == null || data.length == 0) throw new Exception("Data is empty!");

        walletHostAPI.verifyPin(PIN);

        random.nextBytes(data);
        System.out.println("Data for signing = " + hex(data));

        byte[] signatureBytes = walletHostAPI.signShortMessageWithDefaultPath(data);
        System.out.println("signatureBytes = " + hex(signatureBytes));

        assertTrue(signatureBytes  != null);
        assertTrue(signatureBytes.length == SIG_LEN);
        return signatureBytes;
    }

    private void verifySignatureWithDefaultPath(byte[] data, byte[] signatureBytes)  throws Exception {
        System.out.println("From verify Data = " + hex(data));
        System.out.println("From verify SignatureBytes = " + hex(signatureBytes));

        byte[] publicKeyBytesFromCard = walletHostAPI.getPublicKeyWithDefaultHDPath();
        System.out.println("From verify PK = " + hex(publicKeyBytesFromCard));

        verificator.setPublicKey(publicKeyBytesFromCard);
        boolean res =  verificator.verify(data, signatureBytes);

        System.out.println("Verify result = " + res);

        assertTrue(res);
    }
}
