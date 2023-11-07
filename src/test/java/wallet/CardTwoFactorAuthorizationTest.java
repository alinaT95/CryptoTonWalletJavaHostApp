package wallet;

import org.junit.Assert;
import org.junit.Test;
import wallet.common.ByteArrayHelper;
import wallet.tonWalletApi.WalletHostAPI;

import java.util.Random;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertArrayEquals;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.*;

// INSTRUCTION: Before calling each testHelper method here you should reinstall applet in JCIDE simulator
public class CardTwoFactorAuthorizationTest extends CardTest {
    private static short VERIFY_PASSWORD_DATA_LEN = 144;
    private static short MAX_PASSWORD_TRIES = 20;

    private byte[]  password = new byte[PASSWORD_SIZE];
    private  byte[] iv = new byte[IV_SIZE];
    private Random random = new Random();

    @Test
    public void testCorrectPasswordVerification() throws Exception {
        appletStateChecker.checkWaiteAuthorizationState();
        walletHostAPI.readPersonalizationStuffForAppletFromCsv();
        cardTwoFactorAuthorizationHelper.runHashesVerification();
        cardTwoFactorAuthorizationHelper.runSerialNumberVerification();
        //cardTwoFactorAuthorizationHelper.runCorrectPasswordVerification();
    }

    @Test
    public void testWrongLengthForGetHashOfCommonSecret() throws Exception {
        appletStateChecker.checkWaiteAuthorizationState();
        for (int le = 0 ; le < 256; le++) {
            if (le == SHA_HASH_SIZE)
                continue;
            try {
                WalletHostAPI.getWalletCardReaderWrapper().getHashOfEncryptedCommonSecret((byte) le);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
                appletStateChecker.checkWaiteAuthorizationState();
            }
        }
       // testCorrectPasswordVerification();
    }

    @Test
    public void testWrongLengthForGetHashOfEncryptedPassword() throws Exception {
        appletStateChecker.checkWaiteAuthorizationState();
        for (int le = 0 ; le < 256; le++) {
            if (le == SHA_HASH_SIZE)
                continue;
            try {
                WalletHostAPI.getWalletCardReaderWrapper().getHashOfEncryptedPassword((byte) le);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
                appletStateChecker.checkWaiteAuthorizationState();
            }
        }
       // testCorrectPasswordVerification();
    }

    @Test
    public void testAppletBlocking() throws Exception {
        appletStateChecker.checkWaiteAuthorizationState();

        for(int i = 0 ; i <  MAX_PASSWORD_TRIES ; i++) {
            try {
                random.nextBytes(password);
                random.nextBytes(iv);
                System.out.println("==================");
                System.out.println("Iteration " + i);
                System.out.println("Incorrect password = " + ByteArrayHelper.hex(password));
                walletHostAPI.verifyPassword(password, iv);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_PASSWORD_FOR_CARD_AUTHENICATION))
                        || e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_PASSWORD_CARD_IS_BLOCKED)));

                byte state = walletHostAPI.getAppletState();
                if (e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_PASSWORD_FOR_CARD_AUTHENICATION))) {
                    assertTrue(state == APP_WAITE_AUTHORIZATION_MODE);
                }

                if (e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_PASSWORD_CARD_IS_BLOCKED))) {
                    assertTrue(state == APP_BLOCKED_MODE);
                    break;
                }
            }
        }
    }

    @Test
    public void testPasswordVerificationFailAndAppletNotBlocking() throws Exception {
        appletStateChecker.checkWaiteAuthorizationState();

        for(int i = 0 ; i <  MAX_PASSWORD_TRIES - 1 ; i++) {
            try {
                random.nextBytes(password);
                random.nextBytes(iv);
                System.out.println("Iteration " + i);
                System.out.println("Incorrect password = " + ByteArrayHelper.hex(password));
                walletHostAPI.verifyPassword(password, iv);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_PASSWORD_FOR_CARD_AUTHENICATION)));
                appletStateChecker.checkWaiteAuthorizationState();
            }
        }

        testCorrectPasswordVerification();
    }

    @Test
    public void testWrongLengthForVerifyPassword() throws Exception {
        appletStateChecker.checkWaiteAuthorizationState();

        for (int len = 0 ; len < 256; len++) {
            if (len == VERIFY_PASSWORD_DATA_LEN)
                continue;

            byte[] data = new byte[len];
            random.nextBytes(data);
            try {
                System.out.println(len + ") Incorrect data = " + ByteArrayHelper.hex(data));
                WalletHostAPI.getWalletCardReaderWrapper().verifyPassword(data);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
                appletStateChecker.checkWaiteAuthorizationState();
            }
        }

       // testCorrectPasswordVerification();
    }
}
