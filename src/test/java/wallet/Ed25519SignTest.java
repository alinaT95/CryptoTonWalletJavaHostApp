package wallet;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import wallet.common.ByteArrayHelper;
import wallet.smartcard.utils.HmacHelper;
import wallet.testHelper.Ed25519SignTestStuff;
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
import static wallet.testHelper.Ed25519SignTestStuff.NUM_OF_ITERATIONS;

public class Ed25519SignTest extends CardTwoFactorAuthorizationTest {
    private final byte[] INCORRECT_PIN = new byte[]{0x36, 0x36, 0x36, 0x36};
    private Random random = Ed25519SignTestStuff.random;
    private Ed25519SignTestStuff ed25519SignTestStuff = new Ed25519SignTestStuff(walletHostAPI);

    // 0 <= keyIndex <= 2^31 - 1
    private String keyIndex = "2147483642"; //m/44'/396'/0'/0'/2147483647'


    @Before
    public void runAuthorization() throws Exception {
        cardTwoFactorAuthorizationHelper.runAuthorization();
    }

    @Test
    public void testSignForLen32ForRandomHdIndexes() throws Exception {
        ed25519SignTestStuff.testSignShortForLen32ForRandomHdIndexes();
    }

    @Test
    public void testSignForAllLengthForRandomHdIndexes() throws Exception {
        ed25519SignTestStuff.testSignShortForAllLengthForRandomHdIndexes();
    }

    @Test
    public void testSignForLen32() throws Exception {
        ed25519SignTestStuff.testSignWithDefaultPathForGivenDataLength(TRANSACTION_HASH_SIZE, keyIndex);
    }

    @Test
    public void testSignForMaxLen() throws Exception {
        ed25519SignTestStuff.testSignWithDefaultPathForGivenDataLength(DATA_FOR_SIGNING_MAX_SIZE_FOR_CASE_WITH_PATH, keyIndex);
    }

    @Test
    public void testSignForMinLen() throws Exception {
        ed25519SignTestStuff.testSignWithDefaultPathForGivenDataLength(DATA_FOR_SIGNING_MIN_LEN, keyIndex);
    }

    @Test
    public void testSignForAllLength() throws Exception {
        for(int len = DATA_FOR_SIGNING_MIN_LEN; len <= DATA_FOR_SIGNING_MAX_SIZE_FOR_CASE_WITH_PATH ; len++){
            System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            ed25519SignTestStuff.testSignWithDefaultPathForGivenDataLength(len, keyIndex);
            System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~n\n\n");
        }
    }

    @Test
    public void testSignWithoutPinVerification()  throws Exception {
        testSignWithoutPinVerification(keyIndex);
    }

    @Test
    public void testSignWithoutPinVerificationForRandomHdIndexes()  throws Exception {
        for (int i = 0; i < NUM_OF_ITERATIONS; i++) {
            int ind = random.nextInt(Integer.MAX_VALUE);
            System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            System.out.println("hdIndex = " + ind);
            System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~n\n\n");
            testSignWithoutPinVerification(Integer.toString(ind));

        }
    }

    @Test
    public void testSignShortWithIncorrectPin()  throws Exception {
        try {
            walletHostAPI.verifyPin(INCORRECT_PIN);
            Assert.assertTrue(false);
        }
        catch (Exception e){
           // e.printStackTrace();
        }
        int ind = random.nextInt(Integer.MAX_VALUE);
        System.out.println("hdIndex = " + ind);
        testSignWithoutPinVerification(Integer.toString(ind));
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
                Integer ind = random.nextInt(Integer.MAX_VALUE);
                System.out.println("hdIndex = " + ind);
                byte [] indBytes = ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex(ind.toString()));
                byte[] dataChunk = bConcat(new byte[]{ 0x00, (byte)(data.length)}, data, new byte[]{(byte)indBytes.length},indBytes, sault);
                byte[] mac = computeMac(dataChunk);
                WalletHostAPI.getWalletCardReaderWrapper().signShortMessage(bConcat(dataChunk, mac), SIG_LEN);
                assertTrue(false);
            }
            catch (Exception e) {
             //   e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_SAULT)));
            }
        }

        testSignForLen32ForRandomHdIndexes();
    }

    @Test
    public void testOneIncorrectHmac() throws Exception {
        HmacHelper.setIsCorrrectKey(false);
        byte[] data = new byte[TRANSACTION_HASH_SIZE];
        try {
            random.nextBytes(data);
            System.out.println("Data for signing = " + hex(data));
            int ind = random.nextInt(Integer.MAX_VALUE);
            System.out.println("hdIndex = " + ind);
            walletHostAPI.signShortMessage(data, Integer.toString(ind));
            Assert.assertTrue(false);
        } catch (Exception e) {
           // e.printStackTrace();
            appletStateChecker.handleMacException(e);
        }
        HmacHelper.setIsCorrrectKey(true);
        testSignForLen32ForRandomHdIndexes();
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
                    int ind = random.nextInt(Integer.MAX_VALUE);
                    System.out.println("hdIndex = " + ind);
                    walletHostAPI.signShortMessage(data, Integer.toString(ind));
                    Assert.assertTrue(false);
                } catch (Exception e) {
                //    e.printStackTrace();
                    Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_APDU_HMAC)) || e.getMessage().contains(ByteArrayHelper.hex(SW_HMAC_VERIFICATION_TRIES_EXPIRED)));
                }
            }
            else {
                break;
            }
        }
        appletStateChecker. checkBlockedState();
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
                    int ind = random.nextInt(Integer.MAX_VALUE);
                    System.out.println("hdIndex = " + ind);
                    walletHostAPI.signShortMessage(data, Integer.toString(ind));
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
        testSignForLen32ForRandomHdIndexes();
    }

    // INSTRUCTION: Before calling each testHelper method here you should reinstall applet in JCIDE simulator, do not run other tests before this testHelper
    @Test
    public void testHmacVerificationFailCounterClearing() throws Exception {
        testOneIncorrectHmac();
        HmacHelper.setIsCorrrectKey(true);
        testSignForLen32ForRandomHdIndexes();
        testNotBlockingAndSuccessfullSigningAfterMacFailing();
    }

    @Test
    public void testKeyIndexEncoding() throws Exception {
        byte[] data = new byte[TRANSACTION_HASH_SIZE];
        for(int i = 0; i < NUM_OF_ITERATIONS; i++) {
            System.out.println("iter = " + i);

            byte[] sault = walletHostAPI.getSault();

            random.nextBytes(data);
            System.out.println("Data for signing = " + hex(data));

            int indLen = random.nextInt(10) + 1;
            byte[] indBytes = new byte[indLen];
            random.nextBytes(indBytes);
            System.out.println("hdIndex = " + ByteArrayHelper.hex(indBytes));

            byte[] dataChunk = bConcat(new byte[]{0x00, (byte) (data.length)}, data, new byte[]{(byte) indBytes.length}, indBytes, sault);
            byte[] mac = computeMac(dataChunk);

            try {
                WalletHostAPI.getWalletCardReaderWrapper().signShortMessage(bConcat(dataChunk, mac), SIG_LEN);
                assertTrue(false);
            } catch (Exception e) {
                //e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_SIGN_DATA_FAILED)));
            }
        }

        testSignForLen32ForRandomHdIndexes();
    }

    @Test
    public void testWrongLengthIncorrectLe() throws Exception {
        byte[] data = new byte[TRANSACTION_HASH_SIZE];
        for (int le = 0 ; le < 256; le++) {
            if (le == SIG_LEN)
                continue;

            System.out.println("Le = " + le);
            byte[] sault = walletHostAPI.getSault();

            random.nextBytes(data);
            System.out.println("Data for signing = " + hex(data));

            int ind = random.nextInt(Integer.MAX_VALUE);
            System.out.println("hdIndex = " + ind);
            byte[] indBytes = ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex(Integer.toString(ind)));

            byte[] dataChunk = bConcat(new byte[]{ 0x00, (byte)(data.length)}, data, new byte[]{(byte)indBytes.length}, indBytes, sault);
            byte[] mac = computeMac(dataChunk);

            try{
                WalletHostAPI.getWalletCardReaderWrapper().signShortMessage(bConcat(dataChunk, mac), (byte) le);
                assertTrue(false);
            }
            catch (Exception e) {
                //e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }

        testSignForLen32ForRandomHdIndexes();
    }

    @Test
    public void testWrongLengthRandomData() throws Exception {
        for (int len = 0 ; len < 256; len++) {
            try {
                byte[] data = new byte[len];
                random.nextBytes(data);
                WalletHostAPI.getWalletCardReaderWrapper().signShortMessage(data, SIG_LEN);
                assertTrue(false);
            }
            catch (Exception e) {
             //   e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }

        testSignForLen32ForRandomHdIndexes();
    }

    @Test
    public void testWrongLengthNoDataAndNoHdIndexForSigning() throws Exception {
        try {
            byte[] tail = new byte[SAULT_LENGTH + HMAC_SHA_SIG_SIZE];
            random.nextBytes(tail);
            byte[] data = bConcat(new byte[]{0x00, 0x00, 0x00}, tail);
            walletHostAPI.getWalletCardReaderWrapper().signShortMessage(data, SIG_LEN);
            assertTrue(false);
        }
        catch (Exception e) {
           // e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
        }
        testSignForLen32ForRandomHdIndexes();
    }

    @Test
    public void testWrongLengthNoDataAndCorrectHdIndexForSigning() throws Exception {
        try {
            byte[] tail = new byte[SAULT_LENGTH + HMAC_SHA_SIG_SIZE];
            random.nextBytes(tail);

            int ind = random.nextInt(Integer.MAX_VALUE);
            System.out.println("hdIndex = " + ind);
            byte[] indBytes = ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex(Integer.toString(ind)));

            byte[] dataChunk = bConcat(new byte[]{0x00, 0x00}, new byte[]{(byte)indBytes.length}, indBytes, tail);
            WalletHostAPI.getWalletCardReaderWrapper().signShortMessage(dataChunk, SIG_LEN);
            assertTrue(false);
        }
        catch (Exception e) {
            //e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
        }
        testSignForLen32ForRandomHdIndexes();
    }

    @Test
    public void testWrongLengthCorrectDataAndNoHdIndexForSigning() throws Exception {
        byte[] data = new byte[TRANSACTION_HASH_SIZE];
        try {
            byte[] tail = new byte[SAULT_LENGTH + HMAC_SHA_SIG_SIZE];
            random.nextBytes(tail);

            random.nextBytes(data);
            System.out.println("Data for signing = " + hex(data));

            byte[] dataChunk = bConcat(new byte[]{0x00, (byte)(data.length)}, data, new byte[]{0x00}, tail);
            WalletHostAPI.getWalletCardReaderWrapper().signShortMessage(dataChunk, SIG_LEN);
            assertTrue(false);
        }
        catch (Exception e) {
           // e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
        }
        testSignForLen32ForRandomHdIndexes();
    }

    @Test
    //check for malformed length of sault|hmac tail
    public void testWrongLengthForCorrectlyFormedDataForSigning() throws Exception {

        // length of tail < than required
        for (int len = 1; len <= DATA_FOR_SIGNING_MAX_SIZE_FOR_CASE_WITH_PATH; len++) {
            try {
                System.out.println("len = " + len);
                byte[] data = new byte[len];
                random.nextBytes(data);

                int ind = random.nextInt(Integer.MAX_VALUE);
                System.out.println("hdIndex = " + ind);
                byte[] indBytes = ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex(Integer.toString(ind)));

                int tailLen = random.nextInt(SAULT_LENGTH + HMAC_SHA_SIG_SIZE);
                byte[] tail = new byte[tailLen];
                random.nextBytes(tail);

                byte[] dataChunk = bConcat(new byte[]{ 0x00, (byte)(data.length)}, data, new byte[]{(byte)indBytes.length}, indBytes, tail);

                WalletHostAPI.getWalletCardReaderWrapper().signShortMessage(dataChunk, SIG_LEN);
                assertTrue(false);
            }
            catch (Exception e) {
               // e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }

        // length of tail  > than required
        int tailLen = SAULT_LENGTH + HMAC_SHA_SIG_SIZE + 1;
        for (int len = 1; len <= DATA_FOR_SIGNING_MAX_SIZE_FOR_CASE_WITH_PATH - 1; len++) {
            try {
                System.out.println("len = " + len);
                byte[] data = new byte[len];
                random.nextBytes(data);

                int ind = random.nextInt(Integer.MAX_VALUE);
                System.out.println("hdIndex = " + ind);
                byte[] indBytes = ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex(Integer.toString(ind)));

                byte[] tail = new byte[tailLen];
                random.nextBytes(tail);

                byte[] dataChunk = bConcat(new byte[]{ 0x00, (byte)(data.length)}, data, new byte[]{(byte)indBytes.length}, indBytes, tail);

                WalletHostAPI.getWalletCardReaderWrapper().signShortMessage(dataChunk, SIG_LEN);
                assertTrue(false);
            }
            catch (Exception e) {
                //e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }

        testSignForLen32ForRandomHdIndexes();
    }

    @Test
    public void testWrongLengthForMalformedDataForSigning() throws Exception {
        for (int len = DATA_FOR_SIGNING_MAX_SIZE_FOR_CASE_WITH_PATH + 1; len <= 253; len++) {
            try {
                System.out.println("len = " + len);
                byte[] data = new byte[len];
                random.nextBytes(data);

                int tailLen = 253 - len;
                byte[] tail = new byte[tailLen];
                random.nextBytes(tail);

                byte[] dataChunk = bConcat(new byte[]{ 0x00, (byte)(data.length)}, data, tail);

                WalletHostAPI.getWalletCardReaderWrapper().signShortMessage(dataChunk, SIG_LEN);
                assertTrue(false);
            }
            catch (Exception e) {
               // e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }

        testSignForLen32ForRandomHdIndexes();
    }

    @Test
    public void testWrongLengthForMalformedHdIndex() throws Exception {
        byte[] data = new byte[DATA_FOR_SIGNING_MAX_SIZE_FOR_CASE_WITH_PATH];
        for (int len = 11; len <= 73; len++) {
            System.out.println("len = " + len);
            try {
                random.nextBytes(data);

                byte[] indBytes = new byte[len];
                random.nextBytes(indBytes);
                System.out.println("hdIndex = " + ByteArrayHelper.hex(indBytes));

                byte[] dataChunk = bConcat(new byte[]{ 0x00, (byte)(data.length)}, data, new byte[]{(byte)indBytes.length}, indBytes);

                WalletHostAPI.getWalletCardReaderWrapper().signShortMessage(dataChunk, SIG_LEN);
                assertTrue(false);
            }
            catch (Exception e) {
              //  e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }

        testSignForLen32ForRandomHdIndexes();
    }

    private void testSignWithoutPinVerification(String hdIndex)  throws Exception {
        byte[] data = new byte[TRANSACTION_HASH_SIZE];
        random.nextBytes(data);
        System.out.println("Data for signing = " + hex(data));
        try {
            walletHostAPI.signShortMessage(data, hdIndex);
            Assert.assertTrue(false);
        }
        catch (Exception e){
          //  e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_SIGN_DATA_FAILED)));
        }

        testSignForLen32ForRandomHdIndexes();
    }







}
