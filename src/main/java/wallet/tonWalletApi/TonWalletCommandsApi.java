package wallet.tonWalletApi;

import wallet.common.ByteArrayHelper;
import wallet.smartcard.readerWrappers.TonWalletCardReaderWrapper;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;

import java.security.MessageDigest;

import static wallet.common.ByteArrayHelper.bConcat;
import static wallet.common.ByteArrayHelper.bSub;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.WalletAppletConstants.HMAC_SHA_SIG_SIZE;
import static wallet.smartcard.utils.HmacHelper.computeMac;

public class TonWalletCommandsApi {

    private TonWalletCardReaderWrapper walletCardReaderWrapper = null;

    private MessageDigest digest;

    public TonWalletCommandsApi() {

    }

    public TonWalletCommandsApi(CardChannel cardChannel) throws Exception {
        walletCardReaderWrapper = new TonWalletCardReaderWrapper(cardChannel);
        digest = MessageDigest.getInstance("SHA-256");
    }

    public TonWalletCardReaderWrapper getWalletCardReaderWrapper() {
        return walletCardReaderWrapper;
    }


    /** Common stuff **/

    public byte getAppInfo() throws CardException {
        byte[] res = walletCardReaderWrapper.getAppInfo(GET_APP_INFO_LE);
        return  res[0];
    }

    /** Personalization APDU commands **/

    public void finishPers() throws CardException {
        walletCardReaderWrapper.finishPers();
    }

    public void setEncryptedPassword(byte[] encryptedPasswordBytes) throws CardException {
        if (encryptedPasswordBytes.length != PASSWORD_SIZE)
            throw new IllegalArgumentException("Bad password length!");
        walletCardReaderWrapper.setEncryptedPassword(encryptedPasswordBytes);
    }

    public void setEncryptedCommonSecret(byte[] commonSecret) throws CardException {
        if (commonSecret.length != COMMON_SECRET_SIZE)
            throw new IllegalArgumentException("Bad length!");
        walletCardReaderWrapper.setEncryptedCommonSecret(commonSecret);
    }

    public void setSerialNumber(byte[] serialNumber) throws CardException {
        if (serialNumber.length != SERIAL_NUMBER_SIZE)
            throw new IllegalArgumentException("Bad length!");
        walletCardReaderWrapper.setSerialNumber(serialNumber);
    }

    // Waite for authentication mode

    public byte[] getHashOfEncryptedPassword() throws CardException {
        return walletCardReaderWrapper.getHashOfEncryptedPassword(SHA_HASH_SIZE);
    }

    public byte[] getHashOfEncryptedCommonSecret() throws CardException {
        return walletCardReaderWrapper.getHashOfEncryptedCommonSecret(SHA_HASH_SIZE);
    }

    public void verifyPassword(byte[] passwordBytes, byte[] initialVector) throws CardException {
        if (passwordBytes.length != PASSWORD_SIZE || initialVector.length != IV_SIZE)
            throw new IllegalArgumentException("Bad length!");
        walletCardReaderWrapper.verifyPassword(bConcat(passwordBytes, initialVector));
    }


    /** Main  mode **/

    public byte[] getSerialNumber() throws CardException {
        return walletCardReaderWrapper.getSerialNumber((byte) SERIAL_NUMBER_SIZE);
    }

    public void verifyPin(byte[] pinBytes) throws Exception {
        if (pinBytes.length != PIN_SIZE)
            throw new IllegalArgumentException("Bad length!");
        byte[] sault = getSault();
        byte[] dataChunk = bConcat(pinBytes, sault);
        byte[] mac = computeMac(dataChunk);
        walletCardReaderWrapper.verifyPin(bConcat(dataChunk, mac));
    }

    public byte[] signShortMessageWithDefaultPath(byte[] dataForSigning) throws Exception {
        if ((2 + dataForSigning.length + SAULT_LENGTH + HMAC_SHA_SIG_SIZE) > APDU_DATA_MAX_SIZE || dataForSigning.length <= 0
                || dataForSigning.length > DATA_FOR_SIGNING_MAX_SIZE)
            throw new Exception("Bad length!");
        byte[] sault = getSault();
        byte[] dataChunk = bConcat(new byte[]{ 0x00, (byte)(dataForSigning.length)}, dataForSigning, sault);
        byte[] mac = computeMac(dataChunk);
        return walletCardReaderWrapper.signShortMessageWithDefaultPath(bConcat(dataChunk, mac), SIG_LEN);
    }

    public byte[] signShortMessage(byte[] dataForSigning, byte[] ind) throws Exception {
        if ((3 + dataForSigning.length + ind.length + SAULT_LENGTH + HMAC_SHA_SIG_SIZE) > APDU_DATA_MAX_SIZE  || dataForSigning.length <= 0 ||
                dataForSigning.length > DATA_FOR_SIGNING_MAX_SIZE_FOR_CASE_WITH_PATH || ind.length > MAX_IND_SIZE)
            throw new Exception("Bad length!");
        byte[] sault = getSault();
        byte[] dataChunk = bConcat(new byte[]{ 0x00, (byte)(dataForSigning.length)}, dataForSigning, new byte[]{(byte)ind.length},ind, sault);
        byte[] mac = computeMac(dataChunk);
        return walletCardReaderWrapper.signShortMessage(bConcat(dataChunk, mac), SIG_LEN);
    }

    public byte[] getPublicKey(byte [] indBytes) throws CardException {
        if (indBytes.length > MAX_IND_SIZE)
            throw new IllegalArgumentException("Bad length!");
        return walletCardReaderWrapper.getPublicKey(indBytes, PUBLIC_KEY_LEN);
    }

    public byte[] getPublicKeyWithDefaultHDPath() throws CardException {
        return walletCardReaderWrapper.getPublicKeyWithDefaultHDPath(PUBLIC_KEY_LEN);
    }

    /** Recovery data apdu **/

    public byte[] getRecoveryDataHash() throws Exception {
        return walletCardReaderWrapper.getRecoveryDataHash();
    }

    public void resetRecoveryData() throws Exception {
        walletCardReaderWrapper.resetRecoveryData();
    }

    public boolean isRecoveryDataSet() throws Exception {
        return !(walletCardReaderWrapper.isRecoveryDataSet()[0] == 0);
    }

    public int getRecoveryDataLen() throws Exception {
        byte[] res = walletCardReaderWrapper.getRecoveryDataLen();
        return ByteArrayHelper.makeShort(res, 0);
    }

    public void addRecoveryData(byte[] recoveryData) throws Exception {
        if(recoveryData.length  == 0  || recoveryData.length > RECOVERY_DATA_MAX_SIZE) {
            throw new IllegalArgumentException("Bad length!");
        }
        int DATA_PORTION_MAX_SIZE = 252;

        int numberOfPackets = recoveryData.length / DATA_PORTION_MAX_SIZE;
        System.out.println(numberOfPackets);
        for (int i = 0; i < numberOfPackets ; i++) {
            System.out.println("packet " + i);
            byte[] chunk = bSub(recoveryData, i * DATA_PORTION_MAX_SIZE, DATA_PORTION_MAX_SIZE);
            byte p1 = i == 0 ? (byte)0x00 : (byte)0x01;
            walletCardReaderWrapper.addRecoveryDataPart(p1, chunk);
        }

        int tailLen = recoveryData.length % DATA_PORTION_MAX_SIZE;

        if(tailLen > 0) {
            byte[] chunk =  bSub(recoveryData, numberOfPackets * DATA_PORTION_MAX_SIZE, tailLen);
            byte p1 = numberOfPackets == 0 ? (byte)0x00 : (byte)0x01;
            walletCardReaderWrapper.addRecoveryDataPart(p1, chunk);
        }

        byte[] hash =  digest.digest(recoveryData);
        walletCardReaderWrapper.addRecoveryDataPart((byte) 0x02, hash);
    }

    public byte[] getRecoveryData() throws Exception {
        int len  = getRecoveryDataLen();
        if (len == 0) throw new IllegalArgumentException("Recovery data is empty");

        int DATA_PORTION_MAX_SIZE = 252;

        byte[] recoveryData = new byte[len];
        int numberOfPackets = len / DATA_PORTION_MAX_SIZE;
        short startPos = 0;

        System.out.println("numberOfPackets = " + numberOfPackets);
        for(int i = 0; i < numberOfPackets; i++) {
            System.out.println("packet " + i);
            byte[] dataChunk = new byte[]{(byte)(startPos >> 8), (byte)(startPos)};
            byte[] res = walletCardReaderWrapper.getRecoveryDataPart(dataChunk, (byte )DATA_PORTION_MAX_SIZE);
            ByteArrayHelper.arrayCopy(res, 0, recoveryData, startPos, DATA_PORTION_MAX_SIZE);
            startPos += DATA_PORTION_MAX_SIZE;
        }

        int tailLen = len % DATA_PORTION_MAX_SIZE;
        if(tailLen > 0) {
            byte[] chunk = new byte[]{(byte)(startPos >> 8), (byte)(startPos)};
            byte[] res = walletCardReaderWrapper.getRecoveryDataPart(chunk, (byte) tailLen);
            ByteArrayHelper.arrayCopy(res, 0, recoveryData, startPos, tailLen);
        }
        return recoveryData;
    }


    /** KeyChain apdu **/


    public byte[] getSault() throws Exception {
        return walletCardReaderWrapper.getSault(SAULT_LENGTH);
    }


    public void resetKeyChain() throws Exception {
        byte[] sault = getSault();
        walletCardReaderWrapper.resetKeyChain(bConcat(sault, computeMac(sault)));
    }

    public int getNumberOfKeys() throws Exception {
        byte[] sault = getSault();
        byte[] res = walletCardReaderWrapper.getNumberOfKeys(bConcat(sault, computeMac(sault)), GET_NUMBER_OF_KEYS_LE);
        return ByteArrayHelper.makeShort(res, 0);
    }

    public void checkKeyHmacConsistency(byte[] keyHmac) throws  Exception {
        if(keyHmac.length  != HMAC_SHA_SIG_SIZE) {
            throw new IllegalArgumentException("Bad length!");
        }
        byte[] sault = getSault();
        byte[] dataChunk = bConcat(keyHmac, sault);
        walletCardReaderWrapper.checkKeyHmacConsistency(bConcat(dataChunk, computeMac(dataChunk)));
    }

    public void checkAvailableVolForNewKey(short keySize) throws Exception {
        byte[] sault = getSault();
        byte[] dataChunk = bConcat(new byte[]{(byte)(keySize >> 8), (byte)(keySize)}, sault);
        walletCardReaderWrapper.checkAvailableVolForNewKey(bConcat(dataChunk, computeMac(dataChunk)));
    }

    public void initiateChangeOfKey(byte[] index) throws Exception {
        if(index.length  != 2) {
            throw new IllegalArgumentException("Bad length!");
        }
        byte[] sault = getSault();
        byte[] dataChunk = bConcat(new byte[]{index[0], index[1]}, sault);
        walletCardReaderWrapper.initiateChangeOfKey(bConcat(dataChunk, computeMac(dataChunk)));
    }

    public byte[] getIndexAndLenOfKeyInKeyChain(byte[] keyHmac) throws Exception {
        if(keyHmac.length  != HMAC_SHA_SIG_SIZE) {
            throw new IllegalArgumentException("Bad length!");
        }
        byte[] sault = getSault();
        byte[] dataChunk = bConcat(keyHmac, sault);
        byte[] res = walletCardReaderWrapper.getIndexAndLenOfKeyInKeyChain(bConcat(dataChunk, computeMac(dataChunk)), GET_KEY_INDEX_IN_STORAGE_AND_LEN_LE);
        //int indexIntStorage = ByteArrayHelper.makeShort(res, 0);
        //int keyLen = ByteArrayHelper.makeShort(res, 2);
        return res;
    }

    public byte[] getKey(int keyLen, byte[] ind) throws Exception {
        if(ind.length  != 2 || keyLen > KEY_CHAIN_SIZE || keyLen <= 0) {
            throw new IllegalArgumentException("Bad length!");
        }
        byte[] key = new byte[keyLen];
        byte[] dataChunk, sault, res;
        int numberOfPackets = keyLen / DATA_PORTION_MAX_SIZE;
        short startPos = 0;

        System.out.println("numberOfPackets = " + numberOfPackets);
        for(int i = 0; i < numberOfPackets; i++) {
            System.out.println("packet " + i);
            sault = getSault();
            System.out.println("sault = " + ByteArrayHelper.hex(sault));
            dataChunk = bConcat(ind, new byte[]{(byte)(startPos >> 8), (byte)(startPos)}, sault);
            res = walletCardReaderWrapper.getKeyChunk(bConcat(dataChunk, computeMac(dataChunk)), (byte )DATA_PORTION_MAX_SIZE);
            ByteArrayHelper.arrayCopy(res, 0, key, startPos, DATA_PORTION_MAX_SIZE);
            startPos += DATA_PORTION_MAX_SIZE;
        }

        int tailLen = keyLen % DATA_PORTION_MAX_SIZE;
        if(tailLen > 0) {
            sault = getSault();
            System.out.println("sault = " + ByteArrayHelper.hex(sault));
            dataChunk = bConcat(ind, new byte[]{(byte)(startPos >> 8), (byte)(startPos)}, sault);
            res = walletCardReaderWrapper.getKeyChunk(bConcat(dataChunk, computeMac(dataChunk)), (byte) tailLen);
            ByteArrayHelper.arrayCopy(res, 0, key, startPos, tailLen);
        }

        return key;
    }

    public void addKey(byte[] keyBytes) throws Exception {
        sendKey(keyBytes, INS_ADD_KEY_CHUNK);
    }

    public void changeKey(byte[] keyBytes) throws Exception {
        sendKey(keyBytes, INS_CHANGE_KEY_CHUNK);
    }

    private void sendKey(byte[] keyBytes, byte ins) throws Exception {
        if(keyBytes.length > KEY_CHAIN_SIZE || keyBytes.length  <= 0) {
            throw new IllegalArgumentException("Bad length!");
        }

        int numberOfPackets = keyBytes.length / DATA_PORTION_MAX_SIZE;

        byte[] keyChunk, dataChunk, sault;

        System.out.println("numberOfPackets = " + numberOfPackets);

        for(int i = 0; i < numberOfPackets; i++) {
            System.out.println("packet " + i);
            sault = getSault();
            System.out.println("sault = " + ByteArrayHelper.hex(sault));
            keyChunk = bSub(keyBytes, i * DATA_PORTION_MAX_SIZE, DATA_PORTION_MAX_SIZE);
            dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
            sendKeyChunk(i == 0, bConcat(dataChunk, computeMac(dataChunk)), ins);
        }

        int tailLen = keyBytes.length % DATA_PORTION_MAX_SIZE;

        if(tailLen > 0) {
            sault = getSault();
            System.out.println("sault = " + ByteArrayHelper.hex(sault));
            keyChunk =  bSub(keyBytes, numberOfPackets * DATA_PORTION_MAX_SIZE, tailLen);
            dataChunk = bConcat(new byte[]{(byte) keyChunk.length}, keyChunk, sault);
            sendKeyChunk(numberOfPackets == 0, bConcat(dataChunk, computeMac(dataChunk)), ins);
        }

        byte[] mac = computeMac(keyBytes);
        sault = getSault();
        System.out.println("sault = " + ByteArrayHelper.hex(sault));
        dataChunk =  bConcat(mac, sault);
        walletCardReaderWrapper.sendKeyChunk((byte) 0x02, ins, bConcat(dataChunk, computeMac(dataChunk)), SEND_CHUNK_LE);
    }

    private void sendKeyChunk(boolean startOfTransmission, byte[] chunk, byte ins) throws Exception {
        walletCardReaderWrapper.sendKeyChunk(startOfTransmission ? (byte)0x00 : (byte)0x01, ins, chunk);
    }

//    public int deleteKey(byte[] index) throws Exception {
//        if(index.length  != 2) {
//            throw new IllegalArgumentException("Bad length!");
//        }
//        byte[] sault = getSault();
//        byte[] dataChunk = bConcat(new byte[]{index[0], index[1]}, sault);
//        byte[] res = walletCardReaderWrapper.deleteKey( bConcat(dataChunk, computeMac(dataChunk)), DELETE_KEY_LE);
//        return ByteArrayHelper.makeShort(res, 0);
//    }

    public int initiateDeleteOfKey(byte[] index) throws Exception {
        if(index.length  != 2) {
            throw new IllegalArgumentException("Bad length!");
        }
        byte[] sault = getSault();
        byte[] dataChunk = bConcat(new byte[]{index[0], index[1]}, sault);
        byte[] res = walletCardReaderWrapper.initiateDeleteOfKey( bConcat(dataChunk, computeMac(dataChunk)), INITIATE_DELETE_KEY_LE);
        return ByteArrayHelper.makeShort(res, 0);
    }

    public int deleteKeyChunk() throws Exception {
        byte[] sault = getSault();
        byte[] dataChunk =  sault;
        byte[] res = walletCardReaderWrapper.deleteKeyChunk(bConcat(dataChunk, computeMac(dataChunk)), DELETE_KEY_CHUNK_LE);
        return res[0];
    }

    public int getDeleteKeyChunkNumOfPackets() throws Exception {
        byte[] sault = getSault();
        byte[] dataChunk =  sault;
        byte[] res = walletCardReaderWrapper.getDeleteKeyChunkNumOfPackets(bConcat(dataChunk, computeMac(dataChunk)), GET_DELETE_KEY_CHUNK_NUM_OF_PACKETS_LE);
        return ByteArrayHelper.makeShort(res, 0);
    }

    public int getDeleteKeyChunkCounter() throws Exception {
        byte[] sault = getSault();
        byte[] dataChunk =  sault;
        byte[] res = walletCardReaderWrapper.getDeleteKeyChunkCounter(bConcat(dataChunk, computeMac(dataChunk)), GET_DELETE_KEY_CHUNK_COUNTER_LE);
        return ByteArrayHelper.makeShort(res, 0);
    }

    public int deleteKeyRecord() throws Exception {
        byte[] sault = getSault();
        byte[] dataChunk =  sault;
        byte[] res = walletCardReaderWrapper.deleteKeyRecord(bConcat(dataChunk, computeMac(dataChunk)), DELETE_KEY_RECORD_LE);
        return res[0];
    }

    public int getDeleteKeyRecordNumOfPackets() throws Exception {
        byte[] sault = getSault();
        byte[] dataChunk =  sault;
        byte[] res = walletCardReaderWrapper.getDeleteKeyRecordNumOfPackets(bConcat(dataChunk, computeMac(dataChunk)), GET_DELETE_KEY_RECORD_NUM_OF_PACKETS_LE);
        return ByteArrayHelper.makeShort(res, 0);
    }

    public int getDeleteKeyRecordCounter() throws Exception {
        byte[] sault = getSault();
        byte[] dataChunk =  sault;
        byte[] res = walletCardReaderWrapper.getDeleteKeyRecordCounter(bConcat(dataChunk, computeMac(dataChunk)), GET_DELETE_KEY_RECORD_COUNTER_LE);
        return ByteArrayHelper.makeShort(res, 0);
    }

    public int getOccupiedStorageSize() throws Exception {
        byte[] sault = getSault();
        byte[] res = walletCardReaderWrapper.getOccupiedSize(bConcat(sault, computeMac(sault)), GET_OCCUPIED_SIZE_LE);
        return ByteArrayHelper.makeShort(res, 0);
    }

    public int getFreeStorageSize() throws Exception {
        byte[] sault = getSault();
        byte[] res = walletCardReaderWrapper.getFreeSize(bConcat(sault, computeMac(sault)), GET_FREE_SIZE_LE);
        return ByteArrayHelper.makeShort(res, 0);
    }

    public byte[] getHmac( byte[] ind) throws  Exception {
        if(ind.length != 2) {
            throw new IllegalArgumentException("Bad length!");
        }
        byte[] sault = getSault();
        byte[] dataChunk = bConcat(ind, sault);
        return walletCardReaderWrapper.getHmac(bConcat(dataChunk, computeMac(dataChunk)),
                (byte) (HMAC_SHA_SIG_SIZE + 2));

    }
}
