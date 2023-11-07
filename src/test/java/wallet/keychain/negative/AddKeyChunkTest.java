package wallet.keychain.negative;

import org.junit.Assert;
import org.junit.Test;
import wallet.tonWalletApi.WalletHostAPI;
import wallet.common.ByteArrayHelper;
import wallet.smartcard.utils.HmacHelper;

import static wallet.common.ByteArrayHelper.bSub;
import static wallet.common.ByteArrayHelper.bytes;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.*;
import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.bConcat;
import static wallet.smartcard.utils.HmacHelper.computeMac;

public class AddKeyChunkTest extends KeyChainImmutabilityBaseTest {

    public static final byte ADD_KEY_CHUNK_LE = 2;
    public static final int NUM_OF_ITER = 1;

    @Test
    public void testIncorrectSault() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        byte[] sault = new byte[SAULT_LENGTH];
        short keySize = DATA_PORTION_MAX_SIZE;
        byte[] keyChunk = new byte[keySize];
        WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey(keySize);
        for(int i = 0; i < NUM_OF_ITER; i++){
            System.out.println("Iter = " + i);
            try {
                byte p1 = (byte) random.nextInt(2);
                random.nextBytes(sault);
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                random.nextBytes(keyChunk);
                System.out.println("keyChunk = " + ByteArrayHelper.hex(keyChunk));
                byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().addKeyChunk(p1, bConcat(dataChunk, computeMac(dataChunk)));
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
        HmacHelper.setIsCorrrectKey(true);
        short keySize = DATA_PORTION_MAX_SIZE;
        byte[] keyChunk = new byte[keySize];
        WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey(keySize);
        byte[] sault = walletHostAPI.getSault();
        System.out.println("sault = " + ByteArrayHelper.hex(sault));
        random.nextBytes(keyChunk);
        System.out.println("keyChunk = " + ByteArrayHelper.hex(keyChunk));
        byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
        WalletHostAPI.getWalletCardReaderWrapper().addKeyChunk((byte)0, bConcat(dataChunk, computeMac(dataChunk)));
        byte[] mac = new byte[HMAC_SHA_SIG_SIZE];
        for(int i = 0; i < NUM_OF_ITER; i++){
            System.out.println("Iter = " + i);
            try {
                random.nextBytes(sault);
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                random.nextBytes(mac);
                System.out.println("mac = " + ByteArrayHelper.hex(mac));
                dataChunk = bConcat(mac, sault);
                WalletHostAPI.getWalletCardReaderWrapper().addKeyChunk((byte) 2, bConcat(dataChunk, computeMac(dataChunk)));
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_SAULT)));
            }
        }
    }

    @Test
    public void testAddTooBigKey() throws Exception {
        // 7F02 — Send the key of length bigger than len that was set by CHECK_AVAILABLE_VOL_FOR_NEW_KEY or bigger than free size.
        HmacHelper.setIsCorrrectKey(true);
        int maxKeySize = 495;
        for(int i = 0; i < NUM_OF_ITER; i++){
            int keySize = random.nextInt(maxKeySize) + 1;
            WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey((short)keySize);
            byte[] keyChunk = new byte[keySize + 1];
            random.nextBytes(keyChunk);
            System.out.println("keySize = " + keySize);
            System.out.println("keyChunk = " + ByteArrayHelper.hex(keyChunk));

            try {
                WalletHostAPI.getTonWalletApi().addKey(keyChunk);
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
        // 7F06 — Conduct Add operation fot the key that already exists in keychain
        HmacHelper.setIsCorrrectKey(true);
        for(String mac : walletHostAPI.getKeyChainData().keySet()) {
            byte[] key = ByteArrayHelper.bytes(walletHostAPI.getKeyChainData().get(mac));
            try {
                walletHostAPI.addKeyIntoKeyChain(key);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_HMAC_EXISTS)));
            }
        }
    }

    @Test
    public void testWrongLcForHmacTransmission() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        short keySize = DATA_PORTION_MAX_SIZE;
        byte[] keyChunk = new byte[keySize];
        WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey(keySize);
        byte[] sault = walletHostAPI.getSault();
        System.out.println("sault = " + ByteArrayHelper.hex(sault));
        random.nextBytes(keyChunk);
        System.out.println("keyChunk = " + ByteArrayHelper.hex(keyChunk));
        byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
        WalletHostAPI.getWalletCardReaderWrapper().addKeyChunk((byte)0, bConcat(dataChunk, computeMac(dataChunk)));
        for(int i = 0; i <= 255; i++){
            System.out.println("Iter = " + i);
            if(i==96) continue;
            byte[] wrongData = new byte[i];
            try {
                random.nextBytes(wrongData);
                System.out.println("bad data = " + ByteArrayHelper.hex(wrongData));
                WalletHostAPI.getWalletCardReaderWrapper().sendKeyChunk((byte) 0x02, INS_ADD_KEY_CHUNK, wrongData, ADD_KEY_CHUNK_LE);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
    }

    @Test
    public void testWrongLeForHmacTransmission() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        short keySize = DATA_PORTION_MAX_SIZE;
        byte[] keyChunk = new byte[keySize];
        WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey(keySize);
        byte[] sault = walletHostAPI.getSault();
        System.out.println("sault = " + ByteArrayHelper.hex(sault));
        random.nextBytes(keyChunk);
        System.out.println("keyChunk = " + ByteArrayHelper.hex(keyChunk));
        byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
        WalletHostAPI.getWalletCardReaderWrapper().addKeyChunk((byte)0, bConcat(dataChunk, computeMac(dataChunk)));
        for(int le = 0; le <= 255; le++){
            if(le == ADD_KEY_CHUNK_LE) continue;
            System.out.println("Le = " + le);
            byte[] mac = computeMac(keyChunk);
            sault = walletHostAPI.getSault();
            System.out.println("sault = " + ByteArrayHelper.hex(sault));
            dataChunk =  bConcat(mac, sault);
            try {
                WalletHostAPI.getWalletCardReaderWrapper().sendKeyChunk((byte) 0x02, INS_ADD_KEY_CHUNK, bConcat(dataChunk, computeMac(dataChunk)), (byte) le);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
    }

    @Test
    public void testWrongLengthRandomData() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        short keySize = DATA_PORTION_MAX_SIZE;
        WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey(keySize);
        for (int len = 0 ; len <= 255; len++) {
            try {
                byte[] data = new byte[len];
                random.nextBytes(data);
                byte p1 = (byte) random.nextInt(2);
                WalletHostAPI.getWalletCardReaderWrapper().addKeyChunk(p1, data);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
    }

    @Test
    public void testWrongLengthNoKeyChunk() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        short keySize = DATA_PORTION_MAX_SIZE;
        WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey(keySize);
        for(int i = 0; i < NUM_OF_ITER; i++) {
            try {
                byte[] tail = new byte[SAULT_LENGTH + HMAC_SHA_SIG_SIZE];
                random.nextBytes(tail);
                byte[] dataChunk = bConcat(new byte[]{0x00}, tail);
                byte p1 = (byte) random.nextInt(2);
                WalletHostAPI.getWalletCardReaderWrapper().addKeyChunk(p1, dataChunk);
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
        short keySize = DATA_PORTION_MAX_SIZE;
        WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey(keySize);
        for (int len = DATA_FOR_SIGNING_MAX_SIZE + 1; len <= 254; len++) {
            try {
                System.out.println("len = " + len);
                byte[] keyChunk = new byte[len];
                random.nextBytes(keyChunk);
                int tailLen = 254 - len;
                byte[] tail = new byte[tailLen];
                random.nextBytes(tail);
                byte[] dataChunk = bConcat(new byte[]{(byte)(keyChunk.length)}, keyChunk, tail);
                byte p1 = (byte) random.nextInt(2);
                WalletHostAPI.getWalletCardReaderWrapper().addKeyChunk(p1, dataChunk);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
    }

    @Test
    //check for malformed length of sault|hmac tail
    public void testWrongLengthForCorrectlyFormedKeyChunk() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        short keySize = DATA_PORTION_MAX_SIZE;
        WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey(keySize);
        // length of tail < than required
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
                WalletHostAPI.getWalletCardReaderWrapper().addKeyChunk(p1, dataChunk);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }

        // length of tail  > than required
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
                WalletHostAPI.getWalletCardReaderWrapper().addKeyChunk(p1, dataChunk);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
    }

    @Test
    public void testIncorrectKeyLength() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        for(int i = 0; i < NUM_OF_ITER; i++) {
            int keySize = random.nextInt(1024) + 2 * DATA_PORTION_MAX_SIZE;
            System.out.println("len = " + keySize);
            byte[] keyBytes = new byte[keySize];
            random.nextBytes(keyBytes);
            int numberOfPackets = keySize / DATA_PORTION_MAX_SIZE;
            int numOfPacketToMiss = random.nextInt(numberOfPackets + 1);
            System.out.println("numOfPacketToMiss = " + numOfPacketToMiss);

            WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey((short) keySize);

            for(int j = 0; j < numberOfPackets; j++) {
                System.out.println("packet " + j);
                if (j != numOfPacketToMiss) {
                    byte[] sault = walletHostAPI.getSault();
                    System.out.println("sault = " + ByteArrayHelper.hex(sault));
                    byte[] keyChunk = bSub(keyBytes, j * DATA_PORTION_MAX_SIZE, DATA_PORTION_MAX_SIZE);
                    byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                    WalletHostAPI.getWalletCardReaderWrapper().addKeyChunk(j == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
                }
            }

            int tailLen = keyBytes.length % DATA_PORTION_MAX_SIZE;
            if(tailLen > 0 && numOfPacketToMiss != numberOfPackets) {
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] keyChunk =  bSub(keyBytes, numberOfPackets * DATA_PORTION_MAX_SIZE, tailLen);
                byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().addKeyChunk(numberOfPackets == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }

            byte[] mac = computeMac(keyBytes);
            byte[] sault = walletHostAPI.getSault();
            System.out.println("sault = " + ByteArrayHelper.hex(sault));
            byte[] dataChunk =  bConcat(mac, sault);
            try {
                WalletHostAPI.getWalletCardReaderWrapper().sendKeyChunk((byte) 0x02, INS_ADD_KEY_CHUNK, bConcat(dataChunk, computeMac(dataChunk)), SEND_CHUNK_LE);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_KEY_LEN_INCORRECT)));
            }
        }
    }

    @Test
    public void testKeyChunkCorruption() throws Exception {
        HmacHelper.setIsCorrrectKey(true);
        for(int i = 0; i < NUM_OF_ITER; i++) {
            int keySize = random.nextInt(1024) + 2 * DATA_PORTION_MAX_SIZE;
            System.out.println("len = " + keySize);
            byte[] keyBytes = new byte[keySize];
            random.nextBytes(keyBytes);
            int numberOfPackets = keySize / DATA_PORTION_MAX_SIZE;
            int numOfPacketToSpoil = random.nextInt(numberOfPackets + 1);
            System.out.println("numOfPacketToSpoil = " + numOfPacketToSpoil);

            WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey((short) keySize);

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
                WalletHostAPI.getWalletCardReaderWrapper().addKeyChunk(j == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
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
                WalletHostAPI.getWalletCardReaderWrapper().addKeyChunk(numberOfPackets == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }

            byte[] mac = computeMac(keyBytes);
            byte[] sault = walletHostAPI.getSault();
            System.out.println("sault = " + ByteArrayHelper.hex(sault));
            byte[] dataChunk =  bConcat(mac, sault);
            try {
                WalletHostAPI.getWalletCardReaderWrapper().sendKeyChunk((byte) 0x02, INS_ADD_KEY_CHUNK, bConcat(dataChunk, computeMac(dataChunk)), SEND_CHUNK_LE);
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
        for(int i = 0; i < NUM_OF_ITER; i++) {
            int keySize = random.nextInt(1024) + 2 * DATA_PORTION_MAX_SIZE;
            System.out.println("len = " + keySize);
            byte[] keyBytes = new byte[keySize];
            random.nextBytes(keyBytes);
            int numberOfPackets = keySize / DATA_PORTION_MAX_SIZE;

            WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey((short) keySize);

            for(int j = 0; j < numberOfPackets; j++) {
                System.out.println("packet " + j);
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] keyChunk = bSub(keyBytes, j * DATA_PORTION_MAX_SIZE, DATA_PORTION_MAX_SIZE);
                byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().addKeyChunk(j == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }

            int tailLen = keyBytes.length % DATA_PORTION_MAX_SIZE;
            if(tailLen > 0 ) {
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] keyChunk =  bSub(keyBytes, numberOfPackets * DATA_PORTION_MAX_SIZE, tailLen);
                byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().addKeyChunk(numberOfPackets == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }

            byte[] mac = new byte[HMAC_SHA_SIG_SIZE];
            random.nextBytes(mac);
            byte[] sault = walletHostAPI.getSault();
            System.out.println("sault = " + ByteArrayHelper.hex(sault));
            byte[] dataChunk =  bConcat(mac, sault);
            try {
                WalletHostAPI.getWalletCardReaderWrapper().sendKeyChunk((byte) 0x02, INS_ADD_KEY_CHUNK, bConcat(dataChunk, computeMac(dataChunk)), SEND_CHUNK_LE);
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
        for(int i = 0; i < NUM_OF_ITER; i++) {
            int keySize = random.nextInt(1024) + 2 * DATA_PORTION_MAX_SIZE;
            System.out.println("len = " + keySize);
            byte[] keyBytes = new byte[keySize];
            random.nextBytes(keyBytes);
            int numberOfPackets = keySize / DATA_PORTION_MAX_SIZE;

            WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey((short) keySize);

            for(int j = 0; j < numberOfPackets; j++) {
                System.out.println("packet " + j);
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] keyChunk = bSub(keyBytes, j * DATA_PORTION_MAX_SIZE, DATA_PORTION_MAX_SIZE);
                byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().addKeyChunk(j == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }

            int tailLen = keyBytes.length % DATA_PORTION_MAX_SIZE;
            if(tailLen > 0 ) {
                byte[] sault = walletHostAPI.getSault();
                System.out.println("sault = " + ByteArrayHelper.hex(sault));
                byte[] keyChunk =  bSub(keyBytes, numberOfPackets * DATA_PORTION_MAX_SIZE, tailLen);
                byte[] dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
                WalletHostAPI.getWalletCardReaderWrapper().addKeyChunk(numberOfPackets == 0 ? (byte)0 : (byte)1, bConcat(dataChunk, computeMac(dataChunk)));
            }
        }
    }

    @Test
    //The size of new key is not set, host forgot to call CHECK_AVAILABLE_VOL_FOR_NEW_KEY
    public void testKeySizeNotSet() throws Exception {
        for(int i = 0; i < NUM_OF_ITER; i++) {
            try {
                int keySize = random.nextInt(MAX_KEY_SIZE_IN_KEYCHAIN) + 1;
                System.out.println("len = " + keySize);
                byte[] keyBytes = new byte[keySize];
                random.nextBytes(keyBytes);
                WalletHostAPI.getTonWalletApi().addKey(keyBytes);
                assertTrue(false);
            } catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_KEY_SIZE_UNKNOWN)));
            }
        }
    }

    @Test
    public void testKeyNumbersExceeded() throws Exception{
        walletHostAPI.resetKeyChain();
        walletHostAPI.addKeys7();
        saveHmacsBeforeTest();
        for(int i = 0; i < NUM_OF_ITER; i++) {
            try {
                int keySize = random.nextInt(MAX_KEY_SIZE_IN_KEYCHAIN) + 1;
                System.out.println("len = " + keySize);
                byte[] keyBytes = new byte[keySize];
                random.nextBytes(keyBytes);
                WalletHostAPI.getTonWalletApi().addKey(keyBytes);
                assertTrue(false);
            } catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_MAX_KEYS_NUMBER_EXCEEDED)));
            }
        }
    }

    @Test
    public void testOneIncorrectMac() throws Exception{
        HmacHelper.setIsCorrrectKey(true);
        int keySize = random.nextInt(MAX_KEY_SIZE_IN_KEYCHAIN) + 1;
        System.out.println("len = " + keySize);
        byte[] keyBytes = new byte[keySize];
        random.nextBytes(keyBytes);
        WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey((short) keySize);

        HmacHelper.setIsCorrrectKey(false);
        try {
            WalletHostAPI.getTonWalletApi().addKey(keyBytes);
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
        int keySize = 1024;
        WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey((short) keySize);
        HmacHelper.setIsCorrrectKey(false);
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                byte[] keyBytes = new byte[keySize];
                random.nextBytes(keyBytes);
                try {
                    WalletHostAPI.getTonWalletApi().addKey(keyBytes);
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
        int keySize = 1024;
        WalletHostAPI.getTonWalletApi().checkAvailableVolForNewKey((short) keySize);
        HmacHelper.setIsCorrrectKey(false);
        for(int i = 0; i < MAX_HMAC_FAIL_TRIES - 1; i++) {
            System.out.println("Iter = " + i);
            byte state = walletHostAPI.getAppletState();
            if (state == APP_PERSONALIZED) {
                byte[] keyBytes = new byte[keySize];
                random.nextBytes(keyBytes);
                try {
                    WalletHostAPI.getTonWalletApi().addKey(keyBytes);
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
