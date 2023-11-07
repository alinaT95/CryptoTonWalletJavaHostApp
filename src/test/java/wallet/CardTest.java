package wallet;

import org.junit.Before;
import wallet.testHelper.AppletStateChecker;
import wallet.testHelper.CardConnector;
import wallet.testHelper.CardTwoFactorAuthorizationHelper;
import wallet.tonWalletApi.WalletHostAPI;

public abstract class CardTest {
    private CardConnector cardConnector;
    protected WalletHostAPI walletHostAPI;
    protected AppletStateChecker appletStateChecker;
    protected CardTwoFactorAuthorizationHelper cardTwoFactorAuthorizationHelper;

    public CardTest() {
        walletHostAPI = new WalletHostAPI();
        cardConnector = new CardConnector(walletHostAPI);
        appletStateChecker = new AppletStateChecker(walletHostAPI);
        cardTwoFactorAuthorizationHelper = new CardTwoFactorAuthorizationHelper(walletHostAPI);
    }

    @Before
    public void connect(){
        cardConnector.connect();
    }
}
