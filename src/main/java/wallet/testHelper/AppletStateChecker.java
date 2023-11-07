package wallet.testHelper;

import org.junit.Assert;
import wallet.common.ByteArrayHelper;
import wallet.tonWalletApi.WalletHostAPI;

import javax.smartcardio.CardException;

import static junit.framework.TestCase.assertTrue;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.SW_HMAC_VERIFICATION_TRIES_EXPIRED;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.SW_INCORRECT_APDU_HMAC;

public class AppletStateChecker {
    private WalletHostAPI walletHostAPI;

    public AppletStateChecker(WalletHostAPI walletHostAPI) {
        this.walletHostAPI = walletHostAPI;
    }

    public  void checkWaiteAuthorizationState() throws CardException {
        byte state = walletHostAPI.getAppletState();
        assertTrue(state == APP_WAITE_AUTHORIZATION_MODE);
    }

    public  void checkWorkingState() throws CardException {
        byte state = walletHostAPI.getAppletState();
        assertTrue(state == APP_PERSONALIZED || state ==  APP_DELETE_KEY_FROM_KEYCHAIN_MODE);
    }

    public void checkPersonalizedState() throws CardException {
        byte state = walletHostAPI.getAppletState();
        assertTrue(state == APP_PERSONALIZED);
    }

    public void checkBlockedState() throws CardException {
        byte state = walletHostAPI.getAppletState();
        assertTrue(state == APP_BLOCKED_MODE);
    }

    public void handleMacException(Exception e) throws Exception{
        Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_APDU_HMAC)) || e.getMessage().contains(ByteArrayHelper.hex(SW_HMAC_VERIFICATION_TRIES_EXPIRED)));
        if (e.getMessage().contains(ByteArrayHelper.hex(SW_HMAC_VERIFICATION_TRIES_EXPIRED))) {
            checkBlockedState();
            //throw new Exception("Test is stopped, applet is blocked");
        }
    }
}
