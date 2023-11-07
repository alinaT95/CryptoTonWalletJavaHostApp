package wallet;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import wallet.common.ByteArrayHelper;
import wallet.smartcard.utils.HmacHelper;
import wallet.testHelper.Ed25519SignWithDefaultPathTestStuff;
import wallet.tonWalletApi.WalletHostAPI;

import java.util.Random;

import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.bConcat;
import static wallet.common.ByteArrayHelper.hex;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.*;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.SW_HMAC_VERIFICATION_TRIES_EXPIRED;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.SW_INCORRECT_APDU_HMAC;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.utils.HmacHelper.computeMac;
import static wallet.testHelper.Ed25519SignWithDefaultPathTestStuff.NUM_OF_ITERATIONS;

public class Ed25519SignWithDefaultPathTest extends CardTwoFactorAuthorizationTest {
    private final byte[] INCORRECT_PIN = new byte[]{0x36, 0x36, 0x36, 0x36};
    private Random random = Ed25519SignWithDefaultPathTestStuff.random;
    private Ed25519SignWithDefaultPathTestStuff ed25519SignWithDefaultPathTestStuff = new Ed25519SignWithDefaultPathTestStuff(walletHostAPI);

    @Before
    public void runAuthorization() throws Exception {
        cardTwoFactorAuthorizationHelper.runAuthorization();
    }

    @Test
    public void testSignWithDefaultPathVsSignShortForLen32() throws Exception {
     ed25519SignWithDefaultPathTestStuff.testSignWithDefaultPathVsSignShortForGivenDataLength(TRANSACTION_HASH_SIZE);
    }

    @Test
    public void testSignWithDefaultPathForLen32() throws Exception {
        ed25519SignWithDefaultPathTestStuff.testSignWithDefaultPathForGivenDataLength(TRANSACTION_HASH_SIZE);
    }

    @Test
    public void testSignWithDefaultPathForMaxLen() throws Exception {
        ed25519SignWithDefaultPathTestStuff.testSignWithDefaultPathForGivenDataLength(DATA_FOR_SIGNING_MAX_SIZE);
    }

    @Test
    public void testSignWithDefaultPathForMinLen() throws Exception {
        ed25519SignWithDefaultPathTestStuff.testSignWithDefaultPathForGivenDataLength(DATA_FOR_SIGNING_MIN_LEN);
    }

    @Test
    public void testSignWithDefaultPathForAllLength() throws Exception {
        for(int len = DATA_FOR_SIGNING_MIN_LEN; len <= DATA_FOR_SIGNING_MAX_SIZE; len++){
            System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            ed25519SignWithDefaultPathTestStuff.testSignWithDefaultPathForGivenDataLength(len);
            System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
        }
    }

    @Test
    public void testWrongLengthIncorrectLe() throws Exception {
        byte[] data = new byte[TRANSACTION_HASH_SIZE];
        for (int le = 0 ; le < 256; le++) {
            if (le == SIG_LEN)
                continue;
            try{
               // walletHostAPI.verifyPin(PIN);
                System.out.println("Le = " + le);
                byte[] sault = walletHostAPI.getSault();
                random.nextBytes(data);
                System.out.println("Data for signing = " + hex(data));
                byte[] dataChunk = bConcat(new byte[]{ 0x00, (byte)(data.length)}, data, sault);
                byte[] mac = computeMac(dataChunk);

                WalletHostAPI.getWalletCardReaderWrapper().signShortMessageWithDefaultPath(bConcat(dataChunk, mac), (byte) le);
                assertTrue(false);
            }
            catch (Exception e) {
               // e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }

        testSignWithDefaultPathForLen32();
    }

    @Test
    public void testWrongLengthRandomData() throws Exception {
        for (int len = 0 ; len < 256; len++) {
            try {
                byte[] data = new byte[len];
                random.nextBytes(data);
                WalletHostAPI.getWalletCardReaderWrapper().signShortMessageWithDefaultPath(data, SIG_LEN);
                assertTrue(false);
            }
            catch (Exception e) {
              //  e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }

        testSignWithDefaultPathForLen32();
    }

    @Test
    //check for malformed length of sault|hmac tail
    public void testWrongLengthForCorrectlyFormedDataForSigning() throws Exception {
        // length of tail < than required
        for (int len = 1; len <= DATA_FOR_SIGNING_MAX_SIZE; len++) {
            try {
                System.out.println("len = " + len);
                byte[] data = new byte[len];
                random.nextBytes(data);

                int tailLen = random.nextInt(SAULT_LENGTH + HMAC_SHA_SIG_SIZE);
                byte[] tail = new byte[tailLen];
                random.nextBytes(tail);

                byte[] dataChunk = bConcat(new byte[]{ 0x00, (byte)(data.length)}, data, tail);

                WalletHostAPI.getWalletCardReaderWrapper().signShortMessageWithDefaultPath(dataChunk, SIG_LEN);
                assertTrue(false);
            }
            catch (Exception e) {
               // e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }

        // length of tail  > than required
        int tailLen = SAULT_LENGTH + HMAC_SHA_SIG_SIZE + 1;
        for (int len = 1; len <= DATA_FOR_SIGNING_MAX_SIZE - 1; len++) {
            try {
                System.out.println("len = " + len);
                byte[] data = new byte[len];
                random.nextBytes(data);

                byte[] tail = new byte[tailLen];
                random.nextBytes(tail);

                byte[] dataChunk = bConcat(new byte[]{ 0x00, (byte)(data.length)}, data, tail);

                WalletHostAPI.getWalletCardReaderWrapper().signShortMessageWithDefaultPath(dataChunk, SIG_LEN);
                assertTrue(false);
            }
            catch (Exception e) {
               // e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }

        testSignWithDefaultPathForLen32();
    }

    @Test
    public void testWrongLengthForMalformedDataForSigning() throws Exception {
        for (int len = DATA_FOR_SIGNING_MAX_SIZE + 1; len <= 253; len++) {
            try {
                System.out.println("len = " + len);
                byte[] data = new byte[len];
                random.nextBytes(data);

                int tailLen = 253 - len;
                byte[] tail = new byte[tailLen];
                random.nextBytes(tail);

                byte[] dataChunk = bConcat(new byte[]{ 0x00, (byte)(data.length)}, data, tail);

                walletHostAPI.getWalletCardReaderWrapper().signShortMessageWithDefaultPath(dataChunk, SIG_LEN);
                assertTrue(false);
            }
            catch (Exception e) {
               // e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }

        testSignWithDefaultPathForLen32();
    }

    @Test
    public void testWrongLengthNoDataForSigning() throws Exception {
        try {
            byte[] tail = new byte[SAULT_LENGTH + HMAC_SHA_SIG_SIZE];
            random.nextBytes(tail);
            byte[] dataChunk = bConcat(new byte[]{0x00, 0x00}, tail);
            WalletHostAPI.getWalletCardReaderWrapper().signShortMessageWithDefaultPath(dataChunk, SIG_LEN);
            assertTrue(false);
        }
        catch (Exception e) {
          //  e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
        }
        testSignWithDefaultPathForLen32();
    }


    @Test
    public void testSignWithDefaultPathWithoutPinVerification()  throws Exception {
        try {
            byte[] data = new byte[TRANSACTION_HASH_SIZE];
            random.nextBytes(data);
            System.out.println("Data for signing = " + hex(data));
            walletHostAPI.signShortMessageWithDefaultPath(data);
            Assert.assertTrue(false);
        }
        catch (Exception e){
          //  e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_SIGN_DATA_FAILED)));
        }
      //  testSignWithDefaultPathForLen32();
    }

    @Test
    public void testSignWithDefaultPathWithIncorrectPin()  throws Exception {
        try {
            walletHostAPI.verifyPin(INCORRECT_PIN);
            Assert.assertTrue(false);
        }
        catch (Exception e){
        }
        testSignWithDefaultPathWithoutPinVerification();
    }

    @Test
    public void testIncorrectSault()  throws Exception {
        byte[] sault = new byte[SAULT_LENGTH];
        byte[] data = new byte[TRANSACTION_HASH_SIZE];
        for(int i = 0 ; i < NUM_OF_ITERATIONS ; i++){
            System.out.println("Iter = " + i);
            walletHostAPI.verifyPin(PIN);
            try {
                random.nextBytes(sault);
                System.out.println("sault = " + hex(sault));
                random.nextBytes(data);
                System.out.println("Data for signing = " + hex(data));
                byte[] dataChunk = bConcat(new byte[]{ 0x00, (byte)(data.length)}, data, sault);
                byte[] mac = computeMac(dataChunk);
                WalletHostAPI.getWalletCardReaderWrapper().signShortMessageWithDefaultPath(bConcat(dataChunk, mac), SIG_LEN);
                assertTrue(false);
            }
            catch (Exception e) {
             //   e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_SAULT)));
            }
        }
        testSignWithDefaultPathForLen32();
    }

    @Test
    public void testOneIncorrectHmac() throws Exception {
        HmacHelper.setIsCorrrectKey(false);
        byte[] data = new byte[TRANSACTION_HASH_SIZE];
        try {
            random.nextBytes(data);
            System.out.println("Data for signing = " + hex(data));
            walletHostAPI.signShortMessageWithDefaultPath(data);

            Assert.assertTrue(false);
        } catch (Exception e) {
           // e.printStackTrace();
            appletStateChecker.handleMacException(e);
        }
        HmacHelper.setIsCorrrectKey(true);
    }

    @Test
    public void testBlockingBecauseOfMacFailing() throws Exception {
        byte[] data = new byte[TRANSACTION_HASH_SIZE];
        HmacHelper.setIsCorrrectKey(false);
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                try {
                    random.nextBytes(data);
                    System.out.println("Data for signing = " + hex(data));
                    walletHostAPI.signShortMessageWithDefaultPath(data);
                    Assert.assertTrue(false);
                } catch (Exception e) {
                   // e.printStackTrace();
                    Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_APDU_HMAC)) || e.getMessage().contains(ByteArrayHelper.hex(SW_HMAC_VERIFICATION_TRIES_EXPIRED)));
                }
            }
            else {
                break;
            }
        }
        appletStateChecker.checkBlockedState();
    }

    // INSTRUCTION: Before calling each testHelper method here you should reinstall applet in JCIDE simulator, do not run other tests before this testHelper
    @Test
    public void testNotBlockingAndSuccessfullSigningAfterMacFailing() throws Exception {
        HmacHelper.setIsCorrrectKey(false);
        byte[] data = new byte[TRANSACTION_HASH_SIZE];
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES - 1; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                try {
                    random.nextBytes(data);
                    System.out.println("Data for signing = " + hex(data));
                    walletHostAPI.signShortMessageWithDefaultPath(data);
                    Assert.assertTrue(false);
                } catch (Exception e) {
                  //  e.printStackTrace();
                    Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_APDU_HMAC)));
                }
            }
            else {
                break;
            }
        }

        HmacHelper.setIsCorrrectKey(true);
        testSignWithDefaultPathForLen32();
    }

    // INSTRUCTION: Before calling each testHelper method here you should reinstall applet in JCIDE simulator, do not run other tests before this testHelper
    @Test
    public void testHmacVerificationFailCounterClearing() throws Exception {
        testOneIncorrectHmac();
        HmacHelper.setIsCorrrectKey(true);
        testSignWithDefaultPathForLen32();
        testNotBlockingAndSuccessfullSigningAfterMacFailing();
    }



}
