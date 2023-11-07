package wallet.keychain.negative;

import org.junit.After;
import org.junit.Before;
import wallet.keychain.KeyChainGetTest;
import wallet.smartcard.utils.HmacHelper;

import java.util.HashSet;
import java.util.Set;

import static junit.framework.TestCase.assertTrue;
import static wallet.smartcard.WalletAppletConstants.APP_BLOCKED_MODE;
import static wallet.smartcard.WalletAppletConstants.APP_PERSONALIZED;

public class KeyChainImmutabilityBaseTest extends KeyChainGetTest {
    private Set<String> hmacsBeforeTest = new HashSet<>();

    @Before
    public void beforeTest() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        walletHostAPI.resetKeyChain();
        addKeys();
        testKeyMiscData();
        saveHmacsBeforeTest();
    }

    @After
    public void afterTest() throws Exception {
        byte state = walletHostAPI.getAppletState();
        if (state == APP_BLOCKED_MODE) return;
       // assertTrue(state == APP_PERSONALIZED);
        checkHostKeyChainData();
        HmacHelper.setIsCorrrectKey(true);
        testKeyMiscData();
        getAndCheckAllKeysFromKeyChain();
    }

    protected void saveHmacsBeforeTest(){
        hmacsBeforeTest.clear();
        hmacsBeforeTest.addAll(walletHostAPI.getKeyChainData().keySet());
    }

    private void checkHostKeyChainData(){
        assertTrue(hmacsBeforeTest.containsAll(walletHostAPI.getKeyChainData().keySet()));
        assertTrue(walletHostAPI.getKeyChainData().keySet().containsAll(hmacsBeforeTest));
    }
}
