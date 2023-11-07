package wallet.keychain.negative;

import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import wallet.tonWalletApi.WalletHostAPI;
import wallet.common.ByteArrayHelper;
import wallet.smartcard.utils.HmacHelper;

import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.bConcat;
import static wallet.smartcard.WalletAppletConstants.APP_DELETE_KEY_FROM_KEYCHAIN_MODE;
import static wallet.smartcard.WalletAppletConstants.DELETE_KEY_RECORD_LE;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.*;
import static wallet.smartcard.utils.HmacHelper.computeMac;

public class DeleteKeyRecordProtocolViolationTest extends DeleteNegativeBase  {
    public static final int NUM_OF_ITER = 10;

    @After
    public void afterForDeleteKeyRecord() throws  Exception{
        byte state = walletHostAPI.getAppletState();
        if (state == APP_DELETE_KEY_FROM_KEYCHAIN_MODE) {
            byte[] res = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
            Assert.assertTrue(index == ByteArrayHelper.makeShort(res, 0));
            Assert.assertTrue(occupiedSize == walletHostAPI.getOccupiedStorageSize());
            Assert.assertTrue(oldAllKeyFromCard.size() == walletHostAPI.getKeyChainData().size());
            Assert.assertTrue(oldAllKeyFromCard.keySet().containsAll(walletHostAPI.getKeyChainData().keySet()));
            Assert.assertTrue(walletHostAPI.getKeyChainData().keySet().containsAll(oldAllKeyFromCard.keySet()));
            testKeyMiscData();
        }
    }

    @Test
    public void testProtocolViolation() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        byte[] sault;
        for(int i = 0; i < NUM_OF_ITER; i++){
            System.out.println("Iter = " + i);
            try {
                sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                WalletHostAPI.getWalletCardReaderWrapper().deleteKeyRecord(bConcat(sault, computeMac(sault)), DELETE_KEY_RECORD_LE);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_DELETE_KEY_CHUNK_IS_NOT_FINISHED)));
            }
        }
    }

}
