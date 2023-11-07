package wallet;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import wallet.common.ByteArrayHelper;
import wallet.testHelper.SaultTestStuff;
import wallet.tonWalletApi.WalletHostAPI;

import static junit.framework.TestCase.assertTrue;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.SW_WRONG_LENGTH;
import static wallet.smartcard.WalletAppletConstants.*;

public class SaultHandlerTest extends CardTwoFactorAuthorizationTest {

    private SaultTestStuff saultStuffTest = new SaultTestStuff(walletHostAPI);


    @Before
    public void runAuthorization() throws Exception {
        cardTwoFactorAuthorizationHelper.runAuthorization();
    }

    @Test
    public void checkSaultRandomness() throws Exception {
        saultStuffTest.checkSaultRandomness();
    }

    @Test
    public void checkSaultProtocol() throws Exception {
       saultStuffTest.checkSaultProtocol();
    }

    @Test
    public void checkWrongLength() throws Exception {
        for (int le = 0 ; le < 256; le++) {
            try {
                if (le == SAULT_LENGTH)
                    continue;
                WalletHostAPI.getWalletCardReaderWrapper().getSault((byte) le);
                assertTrue(false);
            }
            catch (Exception e) {
             //   e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
        checkSaultRandomness();
    }
}
