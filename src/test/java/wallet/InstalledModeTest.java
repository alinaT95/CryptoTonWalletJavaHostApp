package wallet;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import wallet.common.ByteArrayHelper;
import wallet.smartcard.CardState;
import wallet.smartcard.ConsoleNotifier;
import wallet.tonWalletApi.WalletHostAPI;

import javax.smartcardio.CardException;
import java.util.Random;

import static junit.framework.TestCase.assertTrue;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.*;
import static wallet.smartcard.WalletAppletConstants.*;

// INSTRUCTION: Before calling each testHelper method here you should reinstall applet in JCIDE simulator
public class InstalledModeTest {
    protected static WalletHostAPI walletHostAPI = new WalletHostAPI();;
    protected CardState state;
    private Random random = new Random();

    @Before
    public void connect(){

        ConsoleNotifier consoleNotifier = new ConsoleNotifier();

        WalletHostAPI.setAndStartCardsStateWatcher(consoleNotifier);

        try {
            boolean isConnected = false;

            while ( !isConnected) {
                WalletHostAPI.refreshCardState();

                if (WalletHostAPI.getCardReaderWrapperCurState()) { // Card is inserted

                    state = WalletHostAPI.getWalletCardState();

                    switch (state) {
                        case NOT_INSERTED : {
                            System.out.println("Wallet Applet is NOT_INSERTED");
                            break;
                        }
                        case INSTALLED : {
                            System.out.println("Wallet Applet is INSTALLED");
                            isConnected = true;
                            break;
                        }
                        default: { // Card is not empty
                            System.out.println("Wallet Applet is already peronalized. Reinstall it to run this testHelper.");
                            isConnected = true;
                            break;
                        }

                    }

                    try {
                        Thread.sleep(3000);
                    } catch (InterruptedException e1) {
                    }
                }
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }

    @Test
    public void testWrongLengthForSetEncryptedPassword() throws Exception {
        byte state = walletHostAPI.getAppletState();
        assertTrue(state == APP_INSTALLED);
        byte[] password;
        for (int len = 0 ; len < 256; len++) {
            if (len == PASSWORD_SIZE) continue;
            password = new byte[len];
            random.nextBytes(password);
            try {
                System.out.println(len + ") " + ByteArrayHelper.hex(password));
                WalletHostAPI.getWalletCardReaderWrapper().setEncryptedPassword(password);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }

        state = walletHostAPI.getAppletState();
        assertTrue(state == APP_INSTALLED);

        walletHostAPI.personlizeAppletFromCsv();

        state = walletHostAPI.getAppletState();
        assertTrue(state == APP_WAITE_AUTHORIZATION_MODE);
    }

    @Test
    public void testWrongLengthForSetEncryptedCommonSecret() throws Exception {
        checkInstalledState();
        byte[] commonSecret;
        for (int len = 0 ; len < 256; len++) {
            if (len == COMMON_SECRET_SIZE) continue;
            commonSecret = new byte[len];
            random.nextBytes(commonSecret);
            try {
                System.out.println(len + ") " + ByteArrayHelper.hex(commonSecret));
                WalletHostAPI.getWalletCardReaderWrapper().setEncryptedCommonSecret(commonSecret);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }

        checkInstalledState();

        walletHostAPI.personlizeAppletFromCsv();

        byte state = walletHostAPI.getAppletState();
        assertTrue(state == APP_WAITE_AUTHORIZATION_MODE);
    }

    @Test
    public void testProtocolViolationForFinishPers() throws Exception {
        byte[] commonSecret;
        verifyFinishPers();

        commonSecret = new byte[COMMON_SECRET_SIZE - 1];
        random.nextBytes(commonSecret);
        System.out.println("Incorrect common secret = " + ByteArrayHelper.hex(commonSecret));
        try {
            WalletHostAPI.getWalletCardReaderWrapper().setEncryptedCommonSecret(commonSecret);
        }
        catch (Exception e){
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            e.printStackTrace();
        }
        verifyFinishPers();

        commonSecret = new byte[COMMON_SECRET_SIZE];
        random.nextBytes(commonSecret);
        System.out.println("Correct common secret = " + ByteArrayHelper.hex(commonSecret));
        WalletHostAPI.getWalletCardReaderWrapper().setEncryptedCommonSecret(commonSecret);
        verifyFinishPers();

        byte[] password = new byte[PASSWORD_SIZE - 1];
        random.nextBytes(password);
        System.out.println("Incorrect password = " + ByteArrayHelper.hex(password));
        try {
            WalletHostAPI.getWalletCardReaderWrapper().setEncryptedPassword(password);
        }
        catch (Exception e){
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
        }
        verifyFinishPers();

        walletHostAPI.personlizeAppletFromCsv();

        byte state = walletHostAPI.getAppletState();
        assertTrue(state == APP_WAITE_AUTHORIZATION_MODE);
    }

    @Test
    public void testProtocolViolationForFinishPers2() throws Exception {
        verifyFinishPers();

        byte[] password = new byte[PASSWORD_SIZE - 1];
        random.nextBytes(password);
        System.out.println("Incorrect password = " + ByteArrayHelper.hex(password));
        try {
            WalletHostAPI.getWalletCardReaderWrapper().setEncryptedPassword(password);
        }
        catch (Exception e){
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            e.printStackTrace();
        }
        verifyFinishPers();

        password = new byte[PASSWORD_SIZE];
        random.nextBytes(password);
        System.out.println("Password of correct length = " + ByteArrayHelper.hex(password));
        WalletHostAPI.getWalletCardReaderWrapper().setEncryptedPassword(password);
        verifyFinishPers();


        byte[] commonSecret;
        commonSecret = new byte[COMMON_SECRET_SIZE - 1];
        random.nextBytes(commonSecret);
        System.out.println("Incorrect common secret = " + ByteArrayHelper.hex(commonSecret));
        try {
            WalletHostAPI.getWalletCardReaderWrapper().setEncryptedCommonSecret(commonSecret);
        }
        catch (Exception e){
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            e.printStackTrace();
        }
        verifyFinishPers();

        walletHostAPI.personlizeAppletFromCsv();

        byte state = walletHostAPI.getAppletState();
        assertTrue(state == APP_WAITE_AUTHORIZATION_MODE);
    }

    private void verifyFinishPers() throws CardException {
        try {
            WalletHostAPI.getWalletCardReaderWrapper().finishPers();
        }
        catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PERSONALIZATION_NOT_FINISHED)));
        }
        checkInstalledState();
    }

    private void checkInstalledState() throws CardException {
        byte state = walletHostAPI.getAppletState();
        assertTrue(state == APP_INSTALLED);
    }
}
