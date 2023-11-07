package wallet.testHelper;

import org.junit.Assert;
import wallet.common.ByteArrayHelper;
import wallet.tonWalletApi.WalletHostAPI;

import java.security.MessageDigest;
import java.util.Random;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.fail;
import static wallet.common.ByteArrayHelper.hex;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.SW_INCORRECT_PIN;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.SW_RECOVERY_DATA_IS_NOT_SET;

public class RecoveryDataTestHelper {
    public static Random random = new Random();

    private WalletHostAPI walletHostAPI;

    private MessageDigest digest;

    public RecoveryDataTestHelper(WalletHostAPI walletHostAPI) {
        this.walletHostAPI = walletHostAPI;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        }
        catch (Exception e){e.printStackTrace();}
    }

    public void testAddAndGetRecoveryData() throws Exception {
        System.out.println("TEST for addAndGetRecoveryData" );
        for (int i = 1; i <= RECOVERY_DATA_MAX_SIZE; i++) {
            System.out.println("Number of iteration = " + i);
            byte[] data = new byte[i];
            random.nextBytes(data);
            addAndGetRecoveryData(data);
        }
    }

    public void testAddAndGetRecoveryDataButNotReset(int len) throws Exception {
        System.out.println("TEST for addAndGetRecoveryData for len = " + len );
        byte[] data = new byte[len];
        random.nextBytes(data);
        addAndGetRecoveryDataButNotReset(data);
    }

    public void testReset()  throws Exception {
        walletHostAPI.resetRecoveryData();

        boolean isRecoveryDataSet = walletHostAPI.isRecoveryDataSet();
        System.out.println("isRecoveryDataSet = " + isRecoveryDataSet);
        assertTrue(!isRecoveryDataSet);

        try {
            walletHostAPI.getRecoveryDataLen();
            fail();
        }
        catch (Exception e) {
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_RECOVERY_DATA_IS_NOT_SET)));
        }

        try {
            walletHostAPI.getRecoveryDataHash();
            fail();
        }
        catch (Exception e) {
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_RECOVERY_DATA_IS_NOT_SET)));
        }

        try {
            walletHostAPI.getRecoveryData();
            fail();
        }
        catch (Exception e) {
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_RECOVERY_DATA_IS_NOT_SET)));
        }


    }

    public void addAndGetRecoveryData(byte[] recoveryData)  throws Exception {
        // appletStateChecker.checkPersonalizedState();
        if (recoveryData == null || recoveryData.length == 0) throw new Exception("Data is empty!");

        boolean isRecoveryDataSet = walletHostAPI.isRecoveryDataSet();
        System.out.println("isRecoveryDataSet = " + isRecoveryDataSet);
        assertTrue(!isRecoveryDataSet);

        /*int len = walletHostAPI.getRecoveryDataLen();
        System.out.println("len = " + len);
        assertTrue(len == 0);*/

        System.out.println("Recovery data = " + hex(recoveryData));

        walletHostAPI.addtRecoveryData(recoveryData);

        byte[] recoveryDataFromCard = walletHostAPI.getRecoveryData();
        System.out.println("recoveryDataFromCard = " + hex(recoveryDataFromCard));
        assertEquals(ByteArrayHelper.hex(recoveryData), ByteArrayHelper.hex(recoveryDataFromCard));

        byte[] hash = digest.digest(recoveryData);
        byte[] hashFromCard = walletHostAPI.getRecoveryDataHash();
        System.out.println("hash = " + hex(hash));
        System.out.println("hashFromCard = " + hex(hashFromCard));
        assertEquals(ByteArrayHelper.hex(hash), ByteArrayHelper.hex(hashFromCard));

        isRecoveryDataSet = walletHostAPI.isRecoveryDataSet();
        System.out.println("isRecoveryDataSet = " + isRecoveryDataSet);
        assertTrue(isRecoveryDataSet);

        int newLen = walletHostAPI.getRecoveryDataLen();
        System.out.println("newLen = " + newLen);
        assertTrue(recoveryData.length == newLen);

        walletHostAPI.resetRecoveryData();

        isRecoveryDataSet = walletHostAPI.isRecoveryDataSet();
        System.out.println("isRecoveryDataSet = " + isRecoveryDataSet);
        assertTrue(!isRecoveryDataSet);

      /*  len = walletHostAPI.getRecoveryDataLen();
        System.out.println("len = " + len);
        assertTrue(len == 0);*/
    }


    public void addAndGetRecoveryDataButNotReset(byte[] recoveryData)  throws Exception {
        // appletStateChecker.checkPersonalizedState();
        if (recoveryData == null || recoveryData.length == 0) throw new Exception("Data is empty!");

        boolean isRecoveryDataSet = walletHostAPI.isRecoveryDataSet();
        System.out.println("isRecoveryDataSet = " + isRecoveryDataSet);
        assertTrue(!isRecoveryDataSet);

        /*int len = walletHostAPI.getRecoveryDataLen();
        System.out.println("len = " + len);
        assertTrue(len == 0);
*/
        System.out.println("Recovery data = " + hex(recoveryData));

        walletHostAPI.addtRecoveryData(recoveryData);

        byte[] recoveryDataFromCard = walletHostAPI.getRecoveryData();
        System.out.println("recoveryDataFromCard = " + hex(recoveryDataFromCard));
        assertEquals(ByteArrayHelper.hex(recoveryData), ByteArrayHelper.hex(recoveryDataFromCard));

        byte[] hash = digest.digest(recoveryData);
        byte[] hashFromCard = walletHostAPI.getRecoveryDataHash();
        System.out.println("hash = " + hex(hash));
        System.out.println("hashFromCard = " + hex(hashFromCard));
        assertEquals(ByteArrayHelper.hex(hash), ByteArrayHelper.hex(hashFromCard));

        isRecoveryDataSet = walletHostAPI.isRecoveryDataSet();
        System.out.println("isRecoveryDataSet = " + isRecoveryDataSet);
        assertTrue(isRecoveryDataSet);

        int newLen = walletHostAPI.getRecoveryDataLen();
        System.out.println("newLen = " + newLen);
        assertTrue(recoveryData.length == newLen);

    }
}
