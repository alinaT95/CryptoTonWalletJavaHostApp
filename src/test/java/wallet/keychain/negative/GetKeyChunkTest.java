package wallet.keychain.negative;

import org.junit.Assert;
import org.junit.Test;
import wallet.tonWalletApi.WalletHostAPI;
import wallet.common.ByteArrayHelper;
import wallet.smartcard.utils.HmacHelper;

import static junit.framework.TestCase.assertFalse;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.WalletAppletConstants.APP_PERSONALIZED;
import static wallet.smartcard.WalletAppletConstants.MAX_HMAC_FAIL_TRIES;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.*;
import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.bConcat;
import static wallet.smartcard.utils.HmacHelper.computeMac;

public class GetKeyChunkTest extends KeyChainImmutabilityBaseTest {
    public static final int GET_KEY_CHUNK_LC = 68;
    public static final int NUM_OF_ITER = 10;

    @Test
    public void testIncorrectSault() throws Exception {
        byte[] sault = new byte[SAULT_LENGTH];
        HmacHelper.setIsCorrrectKey(true);
        int numberOfKeys = walletHostAPI.getNumberOfKeys();
        short startPos = 0;
        for(int i = 0; i < NUM_OF_ITER; i++){
            System.out.println("Iter = " + i);
            try {
                random.nextBytes(sault);
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                short ind = (short) random.nextInt(numberOfKeys);
                byte[] indBytes = ByteArrayHelper.bytesForShort(ind);
                System.out.println("ind = " + ind);
                byte[] dataChunk = bConcat(new byte[]{indBytes[0], indBytes [1]}, new byte[]{(byte)(startPos >> 8), (byte)(startPos)}, sault);
                WalletHostAPI.getWalletCardReaderWrapper().getKeyChunk(bConcat(dataChunk, computeMac(dataChunk)), (byte)DATA_PORTION_MAX_SIZE);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_SAULT)));
            }
        }
    }

    @Test
    public void testWrongLength() throws Exception {
        for(int i = 0; i <= 255; i++){
            System.out.println("Iter = " + i);
            if(i == GET_KEY_CHUNK_LC) continue;
            byte[] wrongData = new byte[i];
            try {
                random.nextBytes(wrongData);
                System.out.println("bad data = " + ByteArrayHelper.hex(wrongData));
                WalletHostAPI.getWalletCardReaderWrapper().getKeyChunk(wrongData, (byte)DATA_PORTION_MAX_SIZE);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }

        }
    }

    @Test
    public void testIndexOutOfBound() throws Exception{
        // 7F00 — run the command for some ind ≥ numberOfKeys.
        int numberOfKeys = walletHostAPI.getNumberOfKeys();
        try {
            WalletHostAPI.getTonWalletApi().getKey(DATA_PORTION_MAX_SIZE,  ByteArrayHelper.bytesForShort((short)(numberOfKeys + 1)));
            assertTrue(false);
        }
        catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_KEY_INDEX)));
        }
    }

    @Test
    public void testOneIncorrectMac() throws Exception{
        int numberOfKeys = walletHostAPI.getNumberOfKeys();
        HmacHelper.setIsCorrrectKey(false);
        short ind = (short) random.nextInt(numberOfKeys);
        byte[] sault = walletHostAPI.getSault();
        System.out.println("sault = " + ByteArrayHelper.hex(sault));
        System.out.println("ind = " + ind);
        byte[] indBytes = ByteArrayHelper.bytesForShort(ind);
        short startPos = 0;
        byte[] dataChunk = bConcat(new byte[]{indBytes[0], indBytes [1]}, new byte[]{(byte)(startPos >> 8), (byte)(startPos)}, sault);
        try {
            WalletHostAPI.getWalletCardReaderWrapper().getKeyChunk(bConcat(dataChunk, computeMac(dataChunk)), (byte)DATA_PORTION_MAX_SIZE);
            assertTrue(false);
        }
        catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_APDU_HMAC)));
        }

        HmacHelper.setIsCorrrectKey(true);
    }


    @Test
    public void testBlockingBecauseOfMacFailing() throws Exception {
        int numberOfKeys = walletHostAPI.getNumberOfKeys();
        HmacHelper.setIsCorrrectKey(false);
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                short ind = (short) random.nextInt(numberOfKeys);
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                System.out.println("ind = " + ind);
                byte[] indBytes = ByteArrayHelper.bytesForShort(ind);
                short startPos = 0;
                byte[] dataChunk = bConcat(new byte[]{indBytes[0], indBytes [1]}, new byte[]{(byte)(startPos >> 8), (byte)(startPos)}, sault);
                try {
                    WalletHostAPI.getWalletCardReaderWrapper().getKeyChunk(bConcat(dataChunk, computeMac(dataChunk)), (byte)DATA_PORTION_MAX_SIZE);
                    Assert.assertTrue(false);
                } catch (Exception e) {
                    e.printStackTrace();
                    Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_APDU_HMAC)) || e.getMessage().contains(ByteArrayHelper.hex(SW_HMAC_VERIFICATION_TRIES_EXPIRED)));
                }
            }
            else {
                break;
            }
        }
        appletStateChecker.checkBlockedState();
    }

    // INSTRUCTION: Before calling each testHelper method here you should reinstall applet in JCIDE simulator, do not run other tests before this testHelper
    @Test
    public void testNotBlockingAndSuccessfullSigningAfterMacFailing() throws Exception {
        int numberOfKeys = walletHostAPI.getNumberOfKeys();
        HmacHelper.setIsCorrrectKey(false);
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES - 1; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                short ind = (short) random.nextInt(numberOfKeys);
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                System.out.println("ind = " + ind);
                byte[] indBytes = ByteArrayHelper.bytesForShort(ind);
                short startPos = 0;
                byte[] dataChunk = bConcat(new byte[]{indBytes[0], indBytes [1]}, new byte[]{(byte)(startPos >> 8), (byte)(startPos)}, sault);
                try {
                    WalletHostAPI.getWalletCardReaderWrapper().getKeyChunk(bConcat(dataChunk, computeMac(dataChunk)), (byte)DATA_PORTION_MAX_SIZE);
                    Assert.assertTrue(false);
                } catch (Exception e) {
                    e.printStackTrace();
                    Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_APDU_HMAC)));
                }
            }
            else {
                break;
            }
        }
        HmacHelper.setIsCorrrectKey(true);
    }

    // INSTRUCTION: Before calling each testHelper method here you should reinstall applet in JCIDE simulator, do not run other tests before this testHelper
    @Test
    public void testHmacVerificationFailCounterClearing() throws Exception {
        testOneIncorrectMac();
        HmacHelper.setIsCorrrectKey(true);
        testIncorrectSault();
        testNotBlockingAndSuccessfullSigningAfterMacFailing();
    }



    @Test
    public void testNegativeStartPos() throws Exception {
        //) 7F01 — set  startPos < 0.
        testIncorrectStartPosOrLeValue((short) -1, (byte) 1);
    }

    @Test
    public void testNegativeKeyStoreOffset() throws Exception {
        //) 7F01 — set startPos so big that keyStoreOffset=(short)(keyOffsets[ind] + startPos) < 0,
        testIncorrectStartPosOrLeValue((short) 32767, (byte) 1);
    }

  /*  @Test
    public void testZeroLe() throws Exception {
        //) 7F01 — set le=0
        testIncorrectStartPosOrLeValue((short) 0, (byte) 0);
    }*/

    private void testIncorrectStartPosOrLeValue(short startPos, byte le) throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        int numberOfKeys = walletHostAPI.getNumberOfKeys();
        short ind = (short) random.nextInt(numberOfKeys);
        byte[] sault = walletHostAPI.getSault();
        byte[] indBytes = ByteArrayHelper.bytesForShort(ind);
        System.out.println("sault = " + ByteArrayHelper.hex(sault));
        System.out.println("ind = " + ind);
        byte[] dataChunk = bConcat(new byte[]{indBytes[0], indBytes [1]}, new byte[]{(byte)(startPos >> 8), (byte)(startPos)}, sault);
        try {
            WalletHostAPI.getWalletCardReaderWrapper().getKeyChunk(bConcat(dataChunk, computeMac(dataChunk)), le);
            Assert.assertTrue(false);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_KEY_CHUNK_START_OR_LEN)));
        }
    }

    @Test
    public void testOutOfBoundStartPos() throws Exception {
        //) 7F01 — set startPos so big that keyStoreOffset > endPosOfKey (startPos >= keyLen)
        HmacHelper.setIsCorrrectKey(true);
        for(String mac : walletHostAPI.getKeyChainData().keySet()) {
            short ind = (short) ByteArrayHelper.makeShort(WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac)), 0);
            byte[] indBytes = ByteArrayHelper.bytesForShort(ind);
            int keyLen = walletHostAPI.getKeyChainData().get(mac).length() / 2;
            byte[] sault = walletHostAPI.getSault();
            System.out.println("sault = " + ByteArrayHelper.hex(sault));
            System.out.println("ind = " + ind);
            System.out.println("keyLen = " + keyLen);
            short startPos = (short) keyLen;
            byte[] dataChunk = bConcat(new byte[]{indBytes[0], indBytes[1]}, new byte[]{(byte) (startPos >> 8), (byte) (startPos)}, sault);
            try {
                WalletHostAPI.getWalletCardReaderWrapper().getKeyChunk(bConcat(dataChunk, computeMac(dataChunk)), (byte) 1);
                Assert.assertTrue(false);
            } catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_KEY_CHUNK_START_OR_LEN)));
            }
        }
    }


    @Test
    public void testOutOfBoundLe() throws Exception {
        //) 7F01 — set le so big that (short)(keyStoreOffset + le) > (short)(endPosOfKey + 1)
        HmacHelper.setIsCorrrectKey(true);
        for(String mac : walletHostAPI.getKeyChainData().keySet()) {
            short ind = (short) ByteArrayHelper.makeShort(WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac)), 0);
            byte[] indBytes = ByteArrayHelper.bytesForShort(ind);
            int keyLen = walletHostAPI.getKeyChainData().get(mac).length() / 2;
            byte[] sault = walletHostAPI.getSault();
            System.out.println("sault = " + ByteArrayHelper.hex(sault));
            System.out.println("ind = " + ind);
            System.out.println("keyLen = " + keyLen);
            short startPos =  (short) (keyLen - 1);
            byte[] dataChunk = bConcat(new byte[]{indBytes[0], indBytes[1]}, new byte[]{(byte) (startPos >> 8), (byte) (startPos)}, sault);
            try {
                WalletHostAPI.getWalletCardReaderWrapper().getKeyChunk(bConcat(dataChunk, computeMac(dataChunk)), (byte) 2);
                Assert.assertTrue(false);
            } catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_KEY_CHUNK_START_OR_LEN)));
            }
        }
    }


    @Test
    public void testLostPacket() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        walletHostAPI.resetKeyChain();
        walletHostAPI.addKeys10();
        saveHmacsBeforeTest();
        for(String mac : walletHostAPI.getKeyChainData().keySet()) {
            byte[] res = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
            short ind = (short) ByteArrayHelper.makeShort(res, 0);
            byte[] indBytes = ByteArrayHelper.bytesForShort(ind);
            short keyLen = (short) ByteArrayHelper.makeShort(res, 2);
            byte[] key = new byte[keyLen];
            byte[] dataChunk, sault;
            int numberOfPackets = keyLen / DATA_PORTION_MAX_SIZE;
            short startPos = 0;
            int numOfPacketToMiss = random.nextInt(numberOfPackets + 1);
            System.out.println("numberOfPackets = " + numberOfPackets);
            System.out.println("numOfPacketToMiss = " + numOfPacketToMiss);
            for(int i = 0; i < numberOfPackets; i++) {
                System.out.println("packet " + i);
                sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                dataChunk = bConcat(indBytes, new byte[]{(byte)(startPos >> 8), (byte)(startPos)}, sault);
                if(i != numOfPacketToMiss) {
                    res = WalletHostAPI.getWalletCardReaderWrapper().getKeyChunk(bConcat(dataChunk, computeMac(dataChunk)), (byte) DATA_PORTION_MAX_SIZE);
                    ByteArrayHelper.arrayCopy(res, 0, key, startPos, DATA_PORTION_MAX_SIZE);
                }
                startPos += DATA_PORTION_MAX_SIZE;
            }
            int tailLen = keyLen % DATA_PORTION_MAX_SIZE;
            if(tailLen > 0 && numOfPacketToMiss != numberOfPackets) {
                sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                dataChunk = bConcat(indBytes, new byte[]{(byte)(startPos >> 8), (byte)(startPos)}, sault);
                res = WalletHostAPI.getWalletCardReaderWrapper().getKeyChunk(bConcat(dataChunk, computeMac(dataChunk)), (byte) tailLen);
                ByteArrayHelper.arrayCopy(res, 0, key, startPos, tailLen);
            }
            assertFalse(mac.equals(computeMac(key)));
        }
    }
}
