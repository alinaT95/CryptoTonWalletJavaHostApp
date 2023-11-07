package wallet;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import wallet.common.ByteArrayHelper;
import wallet.testHelper.PublicKeyTestStuff;
import wallet.tonWalletApi.WalletHostAPI;

import javax.smartcardio.CardException;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.hex;

import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.*;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.testHelper.PublicKeyTestStuff.NUM_OF_ITERATIONS;

// INSTRUCTION: Before calling each testHelper method here you should reinstall applet in JCIDE simulator
public class PublicKeyTest extends CardTwoFactorAuthorizationTest {
    private final byte[] INCORRECT_PIN = new byte[]{0x36, 0x36, 0x36, 0x36};

    //m/44’/396’/0’/0’/2’ in LV format, first byte 0x13 - length of hd path
    //private final byte[] HD_PATH_BYTES = new byte[] {0x6D,0x2F,0x34,0x34,0x27,0x2F,0x33,0x39,0x36,0x27,0x2F,0x30,0x27,0x2F,0x30,0x27,0x2F,0x33,0x27};
   // private final byte[] HD_PATH_BYTES_IN_LV = new byte[] {0x13,0x6D,0x2F,0x34,0x34,0x27,0x2F,0x33,0x39,0x36,0x27,0x2F,0x30,0x27,0x2F,0x30,0x27,0x2F,0x32,0x27};

    private Random random = new Random();

    private PublicKeyTestStuff publicKeyTestStuff = new PublicKeyTestStuff(walletHostAPI);

    private String keyIndex = publicKeyTestStuff.getKeyIndex();

    @Before
    public void runAuthorization() throws Exception {
        cardTwoFactorAuthorizationHelper.runAuthorization();
    }

    @Test
    public void testGetPubicKeyForDefaultPath() throws Exception {
        walletHostAPI.verifyPin(PIN);
        publicKeyTestStuff.testGetPubicKeyForDefaultPath();
    }

    @Test
    public void testGetPubicKey() throws Exception {
        walletHostAPI.verifyPin(PIN);
        publicKeyTestStuff.testGetPubicKey();
    }

    @Test
    public void testPinExpiredForGetPublicKeyWithDefaultHDPath()  throws Exception {
        for(int i = 0; i < MAX_PIN_TRIES_NUM; i++){
            System.out.println("\n Iter = " + i);
            try {
                walletHostAPI.verifyPin(INCORRECT_PIN);
                Assert.assertTrue(false);
            }
            catch (Exception e){
             //   e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_PIN)) || e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_TRIES_EXPIRED)));
            }
        }
        try {
            walletHostAPI.getPublicKeyWithDefaultHDPath();
        }
        catch (Exception e){
          //  e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_TRIES_EXPIRED)));
        }
    }

    @Test
    public void testPinExpiredForGetPublicKey()  throws Exception {
        for(int i = 0; i < MAX_PIN_TRIES_NUM; i++){
            System.out.println("Iter = " + i);
            try {
                walletHostAPI.verifyPin(INCORRECT_PIN);
                Assert.assertTrue(false);
            }
            catch (Exception e){
               // e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_PIN)) || e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_TRIES_EXPIRED)));
            }
        }
        try {
            walletHostAPI.getPublicKey(ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex(keyIndex)));
        }
        catch (Exception e){
           // e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_TRIES_EXPIRED)));
        }
    }

    @Test
    public void testWrongLengthForGetPublicKeyWithDefaultHDPath()  throws Exception {
        for (int le = 0 ; le < 256; le++) {
            System.out.println("le = " + le);
            if (le == PUBLIC_KEY_LEN)
                continue;
            try {
                WalletHostAPI.getWalletCardReaderWrapper().getPublicKeyWithDefaultHDPath((byte) le);
                assertTrue(false);
            }
            catch (Exception e) {
             //   e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
        testGetPubicKeyForDefaultPath();
    }

    @Test
    public void testWrongLengthForGetPublicKey()  throws Exception {
        for (int le = 0 ; le < 256; le++) {
            System.out.println("le = " + le);
            if (le == PUBLIC_KEY_LEN)
                continue;
            try {
                WalletHostAPI.getWalletCardReaderWrapper().getPublicKey(ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex(keyIndex)), (byte) le);
                assertTrue(false);
            }
            catch (Exception e) {
               // e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }

        for (int len = MAX_IND_SIZE + 1 ; len < 256; len++) {
            byte[] ind = new byte[len];
            random.nextBytes(ind);
            try {
                WalletHostAPI.getWalletCardReaderWrapper().getPublicKey(ind, PUBLIC_KEY_LEN);
                assertTrue(false);
            }
            catch (Exception e) {
             //   e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }

        testGetPubicKeyForDefaultPath();
    }

    @Test
    public void testPublicKeyChangingAfterResetWallet()  throws Exception {
        Set<String> publicKeys =  new HashSet<>();

        for (int i = 0; i < NUM_OF_ITERATIONS; i++) {
            System.out.println("iter = " + i);
            byte[] publicKeyBytes = walletHostAPI.getPublicKeyWithDefaultHDPath();
            publicKeys.add(ByteArrayHelper.hex(publicKeyBytes));

            publicKeyBytes = walletHostAPI.getPublicKey(ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex(keyIndex)));
            publicKeys.add(ByteArrayHelper.hex(publicKeyBytes));

            WalletHostAPI.getWalletCardReaderWrapper().selectCoinManager();
            WalletHostAPI.getWalletCardReaderWrapper().resetWallet();
            WalletHostAPI.getWalletCardReaderWrapper().generateSeed();
            WalletHostAPI.getWalletCardReaderWrapper().getReader().selectAID(INSTANCE_AID);
        }

        System.out.println(publicKeys.size());
        assertTrue(publicKeys.size() == 2 * NUM_OF_ITERATIONS);
    }

    @Test
    public void testGetPublicKeyWithDefaultHDPathAfterResetWalletAndGenerateSeed()  throws Exception {
        byte[] publicKeyBytes = walletHostAPI.getPublicKeyWithDefaultHDPath();

        WalletHostAPI.getWalletCardReaderWrapper().selectCoinManager();
        WalletHostAPI.getWalletCardReaderWrapper().resetWallet();
        WalletHostAPI.getWalletCardReaderWrapper().generateSeed();

        WalletHostAPI.getWalletCardReaderWrapper().getReader().selectAID(INSTANCE_AID);

        byte[] newPublicKeyBytes = walletHostAPI.getPublicKeyWithDefaultHDPath();

        assertTrue(!ByteArrayHelper.hex(publicKeyBytes).equals(ByteArrayHelper.hex(newPublicKeyBytes)));
    }


    @Test
    public void testGetPublicKeyAfterResetWalletAndGenerateSeed()  throws Exception {
        byte[] publicKeyBytes = walletHostAPI.getPublicKey(ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex(keyIndex)));

        WalletHostAPI.getWalletCardReaderWrapper().selectCoinManager();
        WalletHostAPI.getWalletCardReaderWrapper().resetWallet();
        WalletHostAPI.getWalletCardReaderWrapper().generateSeed();

        WalletHostAPI.getWalletCardReaderWrapper().getReader().selectAID(INSTANCE_AID);
        byte[] newPublicKeyBytes = walletHostAPI.getPublicKey(ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex(keyIndex)));

        assertTrue(!ByteArrayHelper.hex(publicKeyBytes).equals(ByteArrayHelper.hex(newPublicKeyBytes)));
    }

    @Test
    public void testResetWallet()  throws Exception {
        WalletHostAPI.getWalletCardReaderWrapper().selectCoinManager();
        WalletHostAPI.getWalletCardReaderWrapper().resetWallet();

        try {
            WalletHostAPI.getWalletCardReaderWrapper().getReader().selectAID(INSTANCE_AID);
            assertTrue(false);
        }
        catch (Exception e)
        {
           // e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_SET_CURVE_FAILED)));
            WalletHostAPI.getWalletCardReaderWrapper().selectCoinManager();
            WalletHostAPI.getWalletCardReaderWrapper().generateSeed();
        }
    }
}
