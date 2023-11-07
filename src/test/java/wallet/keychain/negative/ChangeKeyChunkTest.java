package wallet.keychain.negative;

import org.junit.Assert;
import org.junit.Test;
import wallet.tonWalletApi.WalletHostAPI;
import wallet.common.ByteArrayHelper;
import wallet.smartcard.utils.HmacHelper;

import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.bConcat;
import static wallet.common.ByteArrayHelper.bSub;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.*;
import static wallet.smartcard.utils.HmacHelper.computeMac;

public class ChangeKeyChunkTest extends KeyChainImmutabilityBaseTest {

    public static final int NUM_OF_ITER = 100;

    @Test
    public void testIncorrectSault() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        byte[] sault = new byte[SAULT_LENGTH];
        short keySize = DATA_PORTION_MAX_SIZE;
        byte[] keyChunk = new byte[keySize];

        for(String mac : walletHostAPI.getKeyChainData().keySet()){
            byte[] data = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
            WalletHostAPI.getTonWalletApi().initiateChangeOfKey(bSub(data, 0, 2));
            try {
                byte p1 = (byte) random.nextInt(2);
                random.nextBytes(sault);
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                random.nextBytes(keyChunk);
                System.out.println("keyChunk = " + ByteArrayHelper.hex(keyChunk));
                byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(p1, bConcat(dataChunk, computeMac(dataChunk)));
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_SAULT)));
            }
        }
    }

    @Test
    public void testIncorrectSaultForHmacTransmission() throws Exception {
        for(String mac : walletHostAPI.getKeyChainData().keySet()){
            byte[] data = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
            WalletHostAPI.getTonWalletApi().initiateChangeOfKey(bSub(data, 0, 2));
            byte[] keyBytes = new byte[walletHostAPI.getKeyChainData().get(mac).length() / 2 ];
            random.nextBytes(keyBytes);
            int numberOfPackets = keyBytes.length / DATA_PORTION_MAX_SIZE;
            byte[] keyChunk, dataChunk, sault;

            System.out.println("numberOfPackets = " + numberOfPackets);

            for(int i = 0; i < numberOfPackets; i++) {
                System.out.println("packet " + i);
                sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                keyChunk = bSub(keyBytes, i * DATA_PORTION_MAX_SIZE, DATA_PORTION_MAX_SIZE);
                dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(i == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }

            int tailLen = keyBytes.length % DATA_PORTION_MAX_SIZE;

            if(tailLen > 0) {
                sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                keyChunk =  bSub(keyBytes, numberOfPackets * DATA_PORTION_MAX_SIZE, tailLen);
                dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(numberOfPackets == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }

            try {
                byte[] keyMac = computeMac(keyBytes);
                sault = new byte[SAULT_LENGTH];
                random.nextBytes(sault);
                dataChunk =  bConcat(keyMac, sault);
                WalletHostAPI.getWalletCardReaderWrapper().sendKeyChunk((byte) 2, INS_CHANGE_KEY_CHUNK, bConcat(dataChunk, computeMac(dataChunk)), (byte) 2);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_SAULT)));
            }
        }
    }

    @Test
    public void testWrongLcForHmacTransmission() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        for(String mac : walletHostAPI.getKeyChainData().keySet()) {
            int keySize = walletHostAPI.getKeyChainData().get(mac).length() / 2;
            byte[] keyBytes = new byte[keySize];
            random.nextBytes(keyBytes);
            int numberOfPackets = keySize / DATA_PORTION_MAX_SIZE;
            byte[] data = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
            WalletHostAPI.getTonWalletApi().initiateChangeOfKey(bSub(data, 0, 2));

            for(int j = 0; j < numberOfPackets; j++) {
                System.out.println("packet " + j);
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] keyChunk = bSub(keyBytes, j * DATA_PORTION_MAX_SIZE, DATA_PORTION_MAX_SIZE);
                byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(j == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }

            int tailLen = keyBytes.length % DATA_PORTION_MAX_SIZE;
            if(tailLen > 0 ) {
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] keyChunk =  bSub(keyBytes, numberOfPackets * DATA_PORTION_MAX_SIZE, tailLen);
                byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(numberOfPackets == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }

            for(int i = 0; i <= 255; i++){
                System.out.println("Iter = " + i);
                if(i==96) continue;
                byte[] wrongData = new byte[i];
                try {
                    random.nextBytes(wrongData);
                    System.out.println("bad data = " + ByteArrayHelper.hex(wrongData));
                    WalletHostAPI.getWalletCardReaderWrapper().sendKeyChunk((byte) 0x02, INS_CHANGE_KEY_CHUNK, wrongData, SEND_CHUNK_LE);
                    assertTrue(false);
                }
                catch (Exception e) {
                    e.printStackTrace();
                    Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
                }
            }
        }
    }

    @Test
    public void testWrongLeForHmacTransmission() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        for(String mac : walletHostAPI.getKeyChainData().keySet()){
            int keySize = walletHostAPI.getKeyChainData().get(mac).length() / 2;
            byte[] keyBytes = new byte[keySize];
            random.nextBytes(keyBytes);
            int numberOfPackets = keySize / DATA_PORTION_MAX_SIZE;

            byte[] data = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
            WalletHostAPI.getTonWalletApi().initiateChangeOfKey(bSub(data, 0, 2));

            for(int j = 0; j < numberOfPackets; j++) {
                System.out.println("packet " + j);
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] keyChunk = bSub(keyBytes, j * DATA_PORTION_MAX_SIZE, DATA_PORTION_MAX_SIZE);
                byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(j == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }

            int tailLen = keyBytes.length % DATA_PORTION_MAX_SIZE;
            if(tailLen > 0 ) {
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] keyChunk =  bSub(keyBytes, numberOfPackets * DATA_PORTION_MAX_SIZE, tailLen);
                byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(numberOfPackets == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }


            byte[] keyMac = computeMac(keyBytes);
            random.nextBytes(keyMac);
            for(int le = 0; le <= 255; le++) {
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] dataChunk =  bConcat(keyMac, sault);
                if(le == SEND_CHUNK_LE) continue;
                try {
                    WalletHostAPI.getWalletCardReaderWrapper().sendKeyChunk((byte) 0x02, INS_CHANGE_KEY_CHUNK, bConcat(dataChunk, computeMac(dataChunk)), (byte)le);
                    assertTrue(false);
                } catch (Exception e) {
                    e.printStackTrace();
                    Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
                }
            }
        }
    }

    @Test
    public void testWrongLengthRandomData() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        for(String mac : walletHostAPI.getKeyChainData().keySet()) {
            byte[] data = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
            WalletHostAPI.getTonWalletApi().initiateChangeOfKey(bSub(data, 0, 2));
            for (int len = 0 ; len <= 255; len++) {
                try {
                    data = new byte[len];
                    random.nextBytes(data);
                    byte p1 = (byte) random.nextInt(2);
                    WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(p1, data);
                    assertTrue(false);
                }
                catch (Exception e) {
                    e.printStackTrace();
                    Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
                }
            }
        }
    }

    @Test
    public void testWrongLengthNoKeyChunk() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        for(String mac : walletHostAPI.getKeyChainData().keySet()) {
            byte[] data = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
            WalletHostAPI.getTonWalletApi().initiateChangeOfKey(bSub(data, 0, 2));
            try {
                byte[] tail = new byte[SAULT_LENGTH + HMAC_SHA_SIG_SIZE];
                random.nextBytes(tail);
                byte[] dataChunk = bConcat(new byte[]{0x00}, tail);
                byte p1 = (byte) random.nextInt(2);
                WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(p1, dataChunk);
                assertTrue(false);
            } catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
    }

    @Test
    public void testWrongLengthForMalformedKeyChunk() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        for(String mac : walletHostAPI.getKeyChainData().keySet()) {
            byte[] data = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
            WalletHostAPI.getTonWalletApi().initiateChangeOfKey(bSub(data, 0, 2));
            for (int len = DATA_FOR_SIGNING_MAX_SIZE + 1; len <= 254; len++) {
                try {
                    System.out.println("len = " + len);
                    byte[] keyChunk = new byte[len];
                    random.nextBytes(keyChunk);
                    int tailLen = 254 - len;
                    byte[] tail = new byte[tailLen];
                    random.nextBytes(tail);
                    byte[] dataChunk = bConcat(new byte[]{(byte) (keyChunk.length)}, keyChunk, tail);
                    byte p1 = (byte) random.nextInt(2);
                    WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(p1, dataChunk);
                    assertTrue(false);
                } catch (Exception e) {
                    e.printStackTrace();
                    Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
                }
            }
        }
    }

    @Test
    //check for malformed length of sault|hmac tail
    public void testWrongLengthForCorrectlyFormedKeyChunk() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        for(String mac : walletHostAPI.getKeyChainData().keySet()) {
            byte[] data = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
            WalletHostAPI.getTonWalletApi().initiateChangeOfKey(bSub(data, 0, 2));

            for (int len = 1; len <= DATA_FOR_SIGNING_MAX_SIZE; len++) {
                try {
                    System.out.println("len = " + len);
                    byte[] keyChunk = new byte[len];
                    random.nextBytes(keyChunk);

                    int tailLen = random.nextInt(SAULT_LENGTH + HMAC_SHA_SIG_SIZE);
                    byte[] tail = new byte[tailLen];
                    random.nextBytes(tail);

                    byte[] dataChunk = bConcat(new byte[]{(byte)(keyChunk.length)}, keyChunk, tail);

                    byte p1 = (byte) random.nextInt(2);
                    WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(p1, dataChunk);
                    assertTrue(false);
                }
                catch (Exception e) {
                    e.printStackTrace();
                    Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
                }
            }


            int tailLen = SAULT_LENGTH + HMAC_SHA_SIG_SIZE + 1;
            for (int len = 1; len <= DATA_FOR_SIGNING_MAX_SIZE - 1; len++) {
                try {
                    System.out.println("len = " + len);
                    byte[] keyChunk = new byte[len];
                    random.nextBytes(keyChunk);

                    byte[] tail = new byte[tailLen];
                    random.nextBytes(tail);

                    byte[] dataChunk = bConcat(new byte[]{(byte)(keyChunk.length)}, keyChunk, tail);

                    byte p1 = (byte) random.nextInt(2);
                    WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(p1, dataChunk);
                    assertTrue(false);
                }
                catch (Exception e) {
                    e.printStackTrace();
                    Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
                }
            }


        }
    }

    @Test
    public void testInitiateChangeOfKeyNotCalled() throws Exception {
        for(String mac : walletHostAPI.getKeyChainData().keySet()){
            byte[] keyBytes = new byte[walletHostAPI.getKeyChainData().get(mac).length() / 2 ];
            random.nextBytes(keyBytes);
            try {
                WalletHostAPI.getTonWalletApi().changeKey(keyBytes);
                assertTrue(false);
            } catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_KEY_INDEX_TO_CHANGE)));
            }
        }
    }

    @Test
    public void testAddTooBigKey() throws Exception {
        // 7F02 — Send the key of length bigger than len that was set by CHECK_AVAILABLE_VOL_FOR_NEW_KEY or bigger than free size.
        HmacHelper.setIsCorrrectKey(true);
        for(String mac : walletHostAPI.getKeyChainData().keySet()) {
            int keySize = walletHostAPI.getKeyChainData().get(mac).length() / 2;
            byte[] keyBytes = new byte[keySize + 1];
            random.nextBytes(keyBytes);
            System.out.println("keySize = " + keySize);
            System.out.println("keyChunk = " + ByteArrayHelper.hex(keyBytes));
            byte[] data = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
            WalletHostAPI.getTonWalletApi().initiateChangeOfKey(bSub(data, 0, 2));
            try {
                WalletHostAPI.getTonWalletApi().changeKey(keyBytes);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_KEY_CHUNK_LEN)));
            }
        }
    }

    @Test
    public void testAddExistingKey() throws Exception {
        // 7F06 — Conduct Change operation fot the key that already exists in keychain
        HmacHelper.setIsCorrrectKey(true);
        for(String mac : walletHostAPI.getKeyChainData().keySet()) {
            byte[] key = ByteArrayHelper.bytes(walletHostAPI.getKeyChainData().get(mac));
            try {
                walletHostAPI.changeKeyInKeyChain(key, ByteArrayHelper.bytes(mac));
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_HMAC_EXISTS)));
            }
        }
    }

    @Test
    public void testKeyChunkCorruption() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        walletHostAPI.resetKeyChain();
        walletHostAPI.addKeys10();
        saveHmacsBeforeTest();
        for(String mac : walletHostAPI.getKeyChainData().keySet()){
            int keySize = walletHostAPI.getKeyChainData().get(mac).length() / 2;
            byte[] keyBytes = new byte[keySize];
            random.nextBytes(keyBytes);
            int numberOfPackets = keySize / DATA_PORTION_MAX_SIZE;
            int numOfPacketToSpoil = random.nextInt(numberOfPackets + 1);
            System.out.println("numOfPacketToSpoil = " + numOfPacketToSpoil);

            byte[] data = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
            WalletHostAPI.getTonWalletApi().initiateChangeOfKey(bSub(data, 0, 2));

            for(int j = 0; j < numberOfPackets; j++) {
                System.out.println("packet " + j);
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] keyChunk;
                if (j != numOfPacketToSpoil) {
                    keyChunk = bSub(keyBytes, j * DATA_PORTION_MAX_SIZE, DATA_PORTION_MAX_SIZE);
                }
                else {
                    keyChunk = new byte[DATA_PORTION_MAX_SIZE];
                    random.nextBytes(keyChunk);
                }
                byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(j == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }

            int tailLen = keyBytes.length % DATA_PORTION_MAX_SIZE;
            if(tailLen > 0 ) {
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] keyChunk;
                if (numOfPacketToSpoil != numberOfPackets) {
                    keyChunk =  bSub(keyBytes, numberOfPackets * DATA_PORTION_MAX_SIZE, tailLen);
                }
                else {
                    keyChunk = new byte[tailLen];
                    random.nextBytes(keyChunk);
                }
                byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(numberOfPackets == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }

            byte[] keyMac = computeMac(keyBytes);
            byte[] sault = walletHostAPI.getSault();
            System.out.println("sault = " + ByteArrayHelper.hex(sault));
            byte[] dataChunk =  bConcat(keyMac, sault);
            try {
                WalletHostAPI.getWalletCardReaderWrapper().sendKeyChunk((byte) 0x02, INS_CHANGE_KEY_CHUNK, bConcat(dataChunk, computeMac(dataChunk)), SEND_CHUNK_LE);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_DATA_INTEGRITY_CORRUPTED)));
            }
        }
    }

    @Test
    public void testKeyMacCorruption() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        walletHostAPI.resetKeyChain();
        walletHostAPI.addKeys10();
        saveHmacsBeforeTest();
        for(String mac : walletHostAPI.getKeyChainData().keySet()) {
            int keySize = walletHostAPI.getKeyChainData().get(mac).length() / 2;
            byte[] keyBytes = new byte[keySize];
            random.nextBytes(keyBytes);
            int numberOfPackets = keySize / DATA_PORTION_MAX_SIZE;

            byte[] data = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
            WalletHostAPI.getTonWalletApi().initiateChangeOfKey(bSub(data, 0, 2));

            for(int j = 0; j < numberOfPackets; j++) {
                System.out.println("packet " + j);
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] keyChunk = bSub(keyBytes, j * DATA_PORTION_MAX_SIZE, DATA_PORTION_MAX_SIZE);
                byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(j == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }

            int tailLen = keyBytes.length % DATA_PORTION_MAX_SIZE;
            if(tailLen > 0 ) {
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] keyChunk =  bSub(keyBytes, numberOfPackets * DATA_PORTION_MAX_SIZE, tailLen);
                byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(numberOfPackets == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }

            byte[] keyMac = new byte[HMAC_SHA_SIG_SIZE];
            random.nextBytes(keyMac);
            byte[] sault = walletHostAPI.getSault();
            System.out.println("sault = " + ByteArrayHelper.hex(sault));
            byte[] dataChunk =  bConcat(keyMac, sault);
            try {
                WalletHostAPI.getWalletCardReaderWrapper().sendKeyChunk((byte) 0x02, INS_CHANGE_KEY_CHUNK, bConcat(dataChunk, computeMac(dataChunk)), SEND_CHUNK_LE);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_DATA_INTEGRITY_CORRUPTED)));
            }
        }
    }

    @Test
    public void testKeyMacMissing() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        walletHostAPI.resetKeyChain();
        walletHostAPI.addKeys10();
        saveHmacsBeforeTest();
        for(String mac : walletHostAPI.getKeyChainData().keySet()) {
            int keySize = walletHostAPI.getKeyChainData().get(mac).length() / 2;
            byte[] keyBytes = new byte[keySize];
            random.nextBytes(keyBytes);
            int numberOfPackets = keySize / DATA_PORTION_MAX_SIZE;

            byte[] data = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
            WalletHostAPI.getTonWalletApi().initiateChangeOfKey(bSub(data, 0, 2));

            for(int j = 0; j < numberOfPackets; j++) {
                System.out.println("packet " + j);
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] keyChunk = bSub(keyBytes, j * DATA_PORTION_MAX_SIZE, DATA_PORTION_MAX_SIZE);
                byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(j == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }

            int tailLen = keyBytes.length % DATA_PORTION_MAX_SIZE;
            if(tailLen > 0 ) {
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] keyChunk =  bSub(keyBytes, numberOfPackets * DATA_PORTION_MAX_SIZE, tailLen);
                byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(numberOfPackets == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }
        }
    }

    @Test
    public void testIncorrectKeyLength() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        walletHostAPI.resetKeyChain();
        walletHostAPI.addKeys10();
        saveHmacsBeforeTest();
        for(String mac : walletHostAPI.getKeyChainData().keySet()) {
            int keySize = walletHostAPI.getKeyChainData().get(mac).length() / 2;
            byte[] keyBytes = new byte[keySize];
            random.nextBytes(keyBytes);
            int numberOfPackets = keySize / DATA_PORTION_MAX_SIZE;
            int numOfPacketToMiss = random.nextInt(numberOfPackets + 1);
            System.out.println("numOfPacketToMiss = " + numOfPacketToMiss);

            byte[] data = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(ByteArrayHelper.bytes(mac));
            WalletHostAPI.getTonWalletApi().initiateChangeOfKey(bSub(data, 0, 2));

            for(int j = 0; j < numberOfPackets; j++) {
                System.out.println("packet " + j);
                if (j != numOfPacketToMiss) {
                    byte[] sault = walletHostAPI.getSault();
                    System.out.println("sault = " + ByteArrayHelper.hex(sault));
                    byte[] keyChunk = bSub(keyBytes, j * DATA_PORTION_MAX_SIZE, DATA_PORTION_MAX_SIZE);
                    byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                    WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(j == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
                }
            }

            int tailLen = keyBytes.length % DATA_PORTION_MAX_SIZE;
            if(tailLen > 0 && numOfPacketToMiss != numberOfPackets) {
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] keyChunk =  bSub(keyBytes, numberOfPackets * DATA_PORTION_MAX_SIZE, tailLen);
                byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().changeKeyChunk(numberOfPackets == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }

            byte[] keyMac = computeMac(keyBytes);
            byte[] sault = walletHostAPI.getSault();
            System.out.println("sault = " + ByteArrayHelper.hex(sault));
            byte[] dataChunk =  bConcat(keyMac, sault);
            try {
                WalletHostAPI.getWalletCardReaderWrapper().sendKeyChunk((byte) 0x02, INS_CHANGE_KEY_CHUNK, bConcat(dataChunk, computeMac(dataChunk)), SEND_CHUNK_LE);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_KEY_LEN_INCORRECT)));
            }
        }
    }

    @Test
    public void testOneIncorrectMac() throws Exception{
        HmacHelper.setIsCorrrectKey(true);
        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        int ind = random.nextInt(macs.length);
        byte[] mac = ByteArrayHelper.bytes(macs[ind]);
        byte[] data = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(mac);
        WalletHostAPI.getTonWalletApi().initiateChangeOfKey(bSub(data, 0, 2));
        int keySize = walletHostAPI.getKeyChainData().get(macs[ind]).length() / 2;
        byte[] keyBytes = new byte[keySize];
        random.nextBytes(keyBytes);
        HmacHelper.setIsCorrrectKey(false);
        try {
            WalletHostAPI.getTonWalletApi().changeKey(keyBytes);
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
        HmacHelper.setIsCorrrectKey(true);
        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        int ind = random.nextInt(macs.length);
        byte[] mac = ByteArrayHelper.bytes(macs[ind]);
        byte[] data = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(mac);
        WalletHostAPI.getTonWalletApi().initiateChangeOfKey(bSub(data, 0, 2));
        int keySize = walletHostAPI.getKeyChainData().get(macs[ind]).length() / 2;
        byte[] keyBytes = new byte[keySize];
        HmacHelper.setIsCorrrectKey(false);
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                random.nextBytes(keyBytes);
                try {
                    WalletHostAPI.getTonWalletApi().changeKey(keyBytes);
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
        HmacHelper.setIsCorrrectKey(true);
        String[] macs = walletHostAPI.getKeyChainData().keySet().toArray(new String[walletHostAPI.getKeyChainData().size()]);
        int ind = random.nextInt(macs.length);
        byte[] mac = ByteArrayHelper.bytes(macs[ind]);
        byte[] data = WalletHostAPI.getTonWalletApi().getIndexAndLenOfKeyInKeyChain(mac);
        WalletHostAPI.getTonWalletApi().initiateChangeOfKey(bSub(data, 0, 2));
        int keySize = walletHostAPI.getKeyChainData().get(macs[ind]).length() / 2;
        byte[] keyBytes = new byte[keySize];
        HmacHelper.setIsCorrrectKey(false);
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES - 1; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                random.nextBytes(keyBytes);
                try {
                    WalletHostAPI.getTonWalletApi().changeKey(keyBytes);
                    Assert.assertTrue(false);
                }  catch (Exception e) {
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
        walletHostAPI.addKeys5();
        saveHmacsBeforeTest();
        testNotBlockingAndSuccessfullSigningAfterMacFailing();
    }


}
