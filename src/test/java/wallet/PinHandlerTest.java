package wallet;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import wallet.common.ByteArrayHelper;
import wallet.smartcard.utils.HmacHelper;
import wallet.tonWalletApi.WalletHostAPI;

import java.util.Random;

import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.bConcat;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.*;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.utils.HmacHelper.computeMac;

// INSTRUCTION: Before calling each testHelper method here you should reinstall applet in JCIDE simulator
public class PinHandlerTest extends CardTwoFactorAuthorizationTest {
    private final byte[] INCORRECT_PIN = new byte[]{0x36, 0x36, 0x36, 0x36};
    public static final int VERIFY_PIN_DATA_LEN = 68;
    public static final int NUM_OF_ITER = 10;

    private Random random = new Random();

    @Before
    public void runAuthorization() throws Exception {
        cardTwoFactorAuthorizationHelper.runAuthorization();
    }

    @Test
    public void testCorrectPinVerification() throws Exception {
        try {
            for(int i = 0; i < NUM_OF_ITER; i++) {
                System.out.println("Iter = " + i);
                walletHostAPI.verifyPin(PIN);
            }
        }
        catch (Exception e){
            Assert.assertTrue(false);
        }
    }

    @Test
    public void testOneIncorrectPinVerification() throws Exception {
        try {
            walletHostAPI.verifyPin(INCORRECT_PIN);
            Assert.assertTrue(false);
        }
        catch (Exception e){
            //e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_PIN)) || e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_TRIES_EXPIRED)));
            walletHostAPI.verifyPin(PIN); // reset pin fails counter
        }
    }

    @Test
    public void testPinExpiring()  throws Exception {
        walletHostAPI.resetWalletAndGenerateSeed();
        walletHostAPI.verifyPin(PIN);
        for(int i = 0; i < MAX_PIN_TRIES_NUM - 1; i++){
            System.out.println("Iter = " + i);
            try {
                walletHostAPI.verifyPin(INCORRECT_PIN);
                Assert.assertTrue(false);
            }
            catch (Exception e){
                //e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_PIN)) /*|| e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_TRIES_EXPIRED))*/);
            }
        }
        try {
            walletHostAPI.verifyPin(INCORRECT_PIN);
            Assert.assertTrue(false);
        }
        catch (Exception e){
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_TRIES_EXPIRED)));
        }
        try {
            walletHostAPI.verifyPin(PIN);
            Assert.assertTrue(false);
        }
        catch (Exception e){
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_TRIES_EXPIRED)));
        }
        walletHostAPI.resetWalletAndGenerateSeed();  //reset pin and seed
    }

    @Test
    public void testPinNotExpiring()  throws Exception {
        walletHostAPI.resetWalletAndGenerateSeed();
        walletHostAPI.verifyPin(PIN);

        for(int i = 0; i < MAX_PIN_TRIES_NUM - 1; i++){
            System.out.println("Iter = " + i);
            try {
                walletHostAPI.verifyPin(INCORRECT_PIN);
                Assert.assertTrue(false);
            }
            catch (Exception e){
                //e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_PIN)) /*|| e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_TRIES_EXPIRED))*/);
            }
        }
        try {
            walletHostAPI.verifyPin(PIN);
        }
        catch (Exception e){
            Assert.assertTrue(false);
        }
    }

    @Test
    public void testNumberOfPinCheckFailsClearingAfterSuccess() throws Exception {
        testOneIncorrectPinVerification();
        try {
            walletHostAPI.verifyPin(PIN);
        }
        catch (Exception e){
            Assert.assertTrue(false);
        }
        testPinNotExpiring();
    }

    @Test
    public void testIncorrectSault()  throws Exception {
        byte[] sault = new byte[SAULT_LENGTH];
        for(int i = 0 ; i < NUM_OF_ITER ; i++){
            System.out.println("Iter = " + i);
            try {
                random.nextBytes(sault);
                byte[] dataChunk = bConcat(PIN, sault);
                byte[] mac = computeMac(dataChunk);
                WalletHostAPI.getWalletCardReaderWrapper().verifyPin(bConcat(dataChunk, mac));
                assertTrue(false);
            }
            catch (Exception e) {
               // e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_SAULT)));
            }
        }
        testCorrectPinVerification();
    }

    @Test
    public void testWrongLength()  throws Exception {
        for (int len = 0 ; len < 256; len++) {
            System.out.println("len = " + len);
            if (len == VERIFY_PIN_DATA_LEN)
                continue;
            byte[] data = new byte[len];
            random.nextBytes(data);
            try {
                System.out.println(len + ") Incorrect data = " + ByteArrayHelper.hex(data));
                WalletHostAPI.getWalletCardReaderWrapper().verifyPin(data);
                assertTrue(false);
            }
            catch (Exception e) {
               // e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
        testCorrectPinVerification();
    }

    @Test
    public void testOneIncorrectHmac() throws Exception {
        HmacHelper.setIsCorrrectKey(false);
        try {
            walletHostAPI.verifyPin(PIN);
            Assert.assertTrue(false);
        } catch (Exception e) {
          //  e.printStackTrace();
            appletStateChecker.handleMacException(e);
        }
    }

    @Test
    public void testBlockingBecauseOfMacFailing() throws Exception {
        HmacHelper.setIsCorrrectKey(false);
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                try {
                    walletHostAPI.verifyPin(PIN);
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
    public void testNotBlockingAndSuccessfullPinVerificationAfterMacFailing() throws Exception {
        HmacHelper.setIsCorrrectKey(false);
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES - 1; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                try {
                    walletHostAPI.verifyPin(PIN);
                    Assert.assertTrue(false);
                } catch (Exception e) {
                   // e.printStackTrace();
                    Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_APDU_HMAC)));
                }
            }
            else {
                break;
            }
        }
        HmacHelper.setIsCorrrectKey(true);
        testCorrectPinVerification();
    }

    // INSTRUCTION: Before calling each testHelper method here you should reinstall applet in JCIDE simulator, do not run other tests before this testHelper
    @Test
    public void testHmacVerificationFailCounterClearing() throws Exception {
        testOneIncorrectHmac();
        HmacHelper.setIsCorrrectKey(true);
        testCorrectPinVerification();
        testNotBlockingAndSuccessfullPinVerificationAfterMacFailing();
    }
}
