package wallet.keychain;

import org.junit.Before;
import org.junit.Test;
import wallet.CardTwoFactorAuthorizationTest;
import wallet.common.ByteArrayHelper;
import wallet.smartcard.utils.HmacHelper;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import static junit.framework.TestCase.assertTrue;
import static wallet.smartcard.WalletAppletConstants.APP_WAITE_AUTHORIZATION_MODE;
import static wallet.smartcard.WalletAppletConstants.KEY_CHAIN_SIZE;
import static wallet.smartcard.utils.HmacHelper.computeMac;

public class KeyChainBaseTest extends CardTwoFactorAuthorizationTest {
    protected Random random = new Random();

    static {
        HmacHelper.setIsCorrrectKey(true);
    }

    @Before
    public void runAuthorization() throws Exception {
        cardTwoFactorAuthorizationHelper.runAuthorization();
    }

    @Test
    public void testStorageSize() throws Exception {
        System.out.println("\n\n Storage size testHelper: \n");
        int occupiedSizeAccordingToKeyChainData = walletHostAPI.getOccupiedSizeAccordingToKeyChainData();
        int occupiedSize = walletHostAPI.getOccupiedStorageSize();
        int freeSize = walletHostAPI.getFreeStorageSize();

        System.out.println("\n\n ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        System.out.println("From testStorageSize:");
        System.out.println("Occupied size according to KeyChainData = " + occupiedSizeAccordingToKeyChainData);
        System.out.println("Occupied size = " + occupiedSize);
        System.out.println("Free size = " + freeSize);
        System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ \n");

        assertTrue(occupiedSize + freeSize == KEY_CHAIN_SIZE);
        assertTrue(occupiedSize  == occupiedSizeAccordingToKeyChainData);
        assertTrue(occupiedSize  == walletHostAPI.getOccupiedSizeCounter());
    }

    @Test
    public void testKeyNumbers() throws Exception {
        System.out.println("\n\n Key numbers testHelper: \n");
        assertTrue(walletHostAPI.getNumberOfKeys() == walletHostAPI.getKeyChainData().size());
        System.out.println("From testKeyNumbers: numberOfKeys = " + walletHostAPI.getKeyChainData().size());
    }

    // we check that all hmacs are present in the card, and only them
    @Test
    public void testHmacsSync() throws Exception {
        System.out.println("\n\n Hmacs sync testHelper: \n");
        Map<String, Integer> keyMacsFromCard = walletHostAPI.getAllHmacsOfKeysFromCard();
        assertTrue(keyMacsFromCard.keySet().containsAll(walletHostAPI.getKeyChainData().keySet()));
        assertTrue(walletHostAPI.getKeyChainData().keySet().containsAll(keyMacsFromCard.keySet()));
    }

    @Test
    public void testKeyMiscData() throws Exception {
        testStorageSize();
        testKeyNumbers();
        testHmacsSync();
    }

    @Test
    public void testResetKeyChain() throws Exception {
        System.out.println("\n\n Reset KeyChain testHelper: \n");
        walletHostAPI.resetKeyChain();
        assertTrue(walletHostAPI.getKeyChainData().size() == 0);
        assertTrue(walletHostAPI.getNumberOfKeys() == 0);
        assertTrue(walletHostAPI.getOccupiedStorageSize()== 0);
        assertTrue(walletHostAPI.getFreeStorageSize() == KEY_CHAIN_SIZE);
    }

    protected void addKeys() throws Exception{
        walletHostAPI.addKeys10();
    }
}
