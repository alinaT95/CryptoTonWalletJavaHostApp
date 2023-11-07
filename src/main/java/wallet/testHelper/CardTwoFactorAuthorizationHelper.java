package wallet.testHelper;

import wallet.common.ByteArrayHelper;
import wallet.tonWalletApi.WalletHostAPI;

import javax.smartcardio.CardException;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertArrayEquals;
import static wallet.smartcard.WalletAppletConstants.*;

public class CardTwoFactorAuthorizationHelper {

    private WalletHostAPI walletHostAPI;
    private AppletStateChecker appletStateChecker;

    public CardTwoFactorAuthorizationHelper(WalletHostAPI walletHostAPI) {
        this.walletHostAPI = walletHostAPI;
        appletStateChecker = new AppletStateChecker(this.walletHostAPI);
    }

    public void runAuthorization() throws Exception {
        byte state = walletHostAPI.getAppletState();
        walletHostAPI.readPersonalizationStuffForApplet();
        if (state == APP_WAITE_AUTHORIZATION_MODE) {
            appletStateChecker.checkWaiteAuthorizationState();
            runHashesVerification();
            runCorrectPasswordVerification();
            runSerialNumberVerification();
        }
        appletStateChecker.checkPersonalizedState();
    }

    public void runHashesVerification() throws CardException {
        byte[] hashFromHost = walletHostAPI.getHashOfEncryptedCommonSecret();
        System.out.println("hashFromHost of encrypted CommonSecret = " + ByteArrayHelper.hex(hashFromHost));

        byte[] hashFromCard = walletHostAPI.getHashOfEncryptedCommonSecretFromCard();
        System.out.println("hashFromCard of encrypted CommonSecret = " + ByteArrayHelper.hex(hashFromCard));
        assertArrayEquals(hashFromHost, hashFromCard);

        hashFromHost = walletHostAPI.getHashOfEncryptedPassword();
        System.out.println("hashFromHost of EncryptedPassword = " + ByteArrayHelper.hex(hashFromHost));

        hashFromCard = walletHostAPI.getHashOfEncryptedPasswordFromCard();
        System.out.println("hashFromCard of EncryptedPassword = " + ByteArrayHelper.hex(hashFromCard));
        assertArrayEquals(hashFromHost, hashFromCard);
    }

    public void runSerialNumberVerification() throws CardException {
        byte[] serialNumber = walletHostAPI.getSerialNumber();
        System.out.println("serialNumber = " + ByteArrayHelper.hex(serialNumber));

        byte[] serialNumberFromCard = walletHostAPI.getSerialNumberFromCard();
        System.out.println("serialNumber from card = " + ByteArrayHelper.hex(serialNumberFromCard));
        assertArrayEquals(serialNumber, serialNumberFromCard);
    }

    public void runCorrectPasswordVerification() throws CardException {
        System.out.println("Run correct password verification... ");
        walletHostAPI.verifyPassword();
        byte state = walletHostAPI.getAppletState();
        System.out.println("state = " + state);
        assertTrue(state == APP_PERSONALIZED);
    }


}
