package wallet.smartcard.readerWrappers;

import wallet.smartcard.CardState;
import wallet.smartcard.cardReader.readerImpl.RealCardReader;
import wallet.smartcard.pcscWrapper.CAPDU;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;

import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.utils.HmacHelper.computeMac;

public class TonWalletCardReaderWrapper extends CardReaderWrapper {
    public TonWalletCardReaderWrapper(CardChannel cardChannel) throws Exception {
        reader = new RealCardReader(cardChannel, "Client Reader");
    }

    public CardState getAppletState(String clientAppletAid){
        CardState cardState = CardState.NOT_INSERTED;

        if (reader.getApduRunner().getChannel() != null ) {

            try {

                reader.selectAID(clientAppletAid);
                byte[] res = getAppInfo(GET_APP_INFO_LE);
                byte clientAppState = res[0];

                System.out.println("applet state = " + clientAppState);


                if (clientAppState == APP_PERSONALIZED || clientAppState == APP_DELETE_KEY_FROM_KEYCHAIN_MODE ) {
                    cardState = CardState.ON_GOING;
                }
                else if (clientAppState == APP_WAITE_AUTHORIZATION_MODE){
                    cardState = CardState.WAIT_AUTHENTICATION;
                }
                else if (clientAppState == APP_BLOCKED_MODE){
                    cardState = CardState.BLOCKED;
                }
                else if (clientAppState == APP_INSTALLED){
                    cardState = CardState.INSTALLED;
                }
                else{
                    cardState = CardState.INVALID;
                }

                System.out.println("cardState = " + cardState); /**/

            } catch (/*Card*/Exception e) {
                e.printStackTrace();
                cardState = CardState.EMPTY;
            }
        }
        return cardState;
    }

    // CoinManager Stuff

    public void selectCoinManager() throws CardException {
        reader.sendAPDU(new CAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00));
    }

    public void resetWallet() throws CardException {
        reader.sendAPDU(new CAPDU((byte) 0x80, (byte) 0xCB, (byte) 0x80, (byte) 0x00, new byte[]{(byte)0xDF, (byte)0xFE, (byte)0x02, (byte)0x82, (byte)0x05}));
    }

    public void generateSeed() throws CardException {
        reader.sendAPDU(new CAPDU((byte) 0x80,
                (byte) 0xCB,
                (byte) 0x80,
                (byte) 0x00,
                new byte[]{(byte)0xDF, (byte)0xFE, (byte)0x08, (byte)0x82, (byte)0x03, (byte)0x05, (byte)0x04, (byte)0x35, (byte)0x35, (byte)0x35, (byte)0x35}));
    }

    /** Common stuff **/

    public byte[] getAppInfo(byte le) throws CardException {
        return reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_GET_APP_INFO, (byte) 0x00, (byte) 0x00, le)).getData();
    }

    /**  Personalization APDU commands **/

    public void finishPers() throws CardException {
        reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_FINISH_PERS, 0x00, 0x00));
    }

    public void setEncryptedPassword(byte[] data) throws CardException {
        reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_SET_ENCRYPTED_PASSWORD_FOR_CARD_AUTHENTICATION, 0x00, 0x00, data));
    }

    public void setEncryptedCommonSecret(byte[] data) throws CardException {
        reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_SET_ENCRYPTED_COMMON_SECRET, 0x00, 0x00, data));
    }

    public void setSerialNumber(byte[] data) throws CardException {
        reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_SET_SERIAL_NUMBER, 0x00, 0x00, data));
    }

    public byte[] getSerialNumber(byte le) throws CardException {
        return reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_GET_SERIAL_NUMBER, 0x00, 0x00, le)).getData();
    }

    public byte[] getHashOfEncryptedPassword(byte le) throws CardException {
        return reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_GET_HASH_OF_ENCRYPTED_PASSWORD, 0x00, 0x00, le)).getData();
    }

    public byte[] getHashOfEncryptedCommonSecret(byte le) throws CardException {
        return reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_GET_HASH_OF_ENCRYPTED_COMMON_SECRET, 0x00, 0x00, le)).getData();
    }

    public void verifyPassword(byte[] data) throws CardException {
        reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_VERIFY_PASSWORD, 0x00, 0x00, data));
    }

    public void verifyPin(byte[] data) throws Exception {
        reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_VERIFY_PIN, 0x00, 0x00,  data));
    }

    public void addRecoveryDataPart(byte p1, byte[] data) throws Exception {
        reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_ADD_RECOVERY_DATA_PART,
                p1, (byte)0x00,
                data));
    }

    public byte[] getRecoveryDataPart(byte[] startPositionBytes, byte le) throws Exception {
        return reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_GET_RECOVERY_DATA_PART,
                (byte)0x00, (byte)0x00,
                startPositionBytes,
                le)).getData();
    }

    public byte[] getRecoveryDataHash() throws Exception {
        return reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_GET_RECOVERY_DATA_HASH,
                (byte)0x00, (byte)0x00,
                SHA_HASH_SIZE)).getData();
    }

    public byte[] getRecoveryDataHash(int le) throws Exception {
        return reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_GET_RECOVERY_DATA_HASH,
                (byte)0x00, (byte)0x00,
                le)).getData();
    }

    public byte[] getRecoveryDataLen() throws Exception {
        return reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_GET_RECOVERY_DATA_LEN,
                (byte)0x00, (byte)0x00,
                0x02)).getData();
    }

    public byte[] getRecoveryDataLen(int le) throws Exception {
        return reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_GET_RECOVERY_DATA_LEN,
                (byte)0x00, (byte)0x00,
                le)).getData();
    }

    public void resetRecoveryData() throws Exception {
        reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_RESET_RECOVERY_DATA,
                (byte)0x00, (byte)0x00));
    }

    public byte[] isRecoveryDataSet() throws Exception {
        return reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_IS_RECOVERY_DATA_SET,
                (byte)0x00, (byte)0x00, 0x01)).getData();
    }

    public byte[] isRecoveryDataSet(int  le) throws Exception {
        return reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_IS_RECOVERY_DATA_SET,
                (byte)0x00, (byte)0x00, le)).getData();
    }

    public byte[] signShortMessageWithDefaultPath(byte[] data, byte le) throws Exception {
        return reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_SIGN_SHORT_MESSAGE_WITH_DEFAULT_PATH,
                (byte)0x00, (byte)0x00,
                data,
                le)).getData();
    }

    public byte[] signShortMessage(byte[] data, byte le) throws Exception {
        return reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_SIGN_SHORT_MESSAGE,
                (byte)0x00, (byte)0x00,
                data,
                le)).getData();
    }

    public byte[] getPublicKey(byte[] data, byte le) throws CardException {
        return reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_GET_PUBLIC_KEY,
                (byte) 0x00, (byte) 0x00,
                data,
                le)).getData();
    }

    public byte[] getPublicKeyWithDefaultHDPath(byte le) throws CardException {
        return reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_GET_PUBLIC_KEY_WITH_DEFAULT_HD_PATH,
                0x00, 0x00,
                le)).getData();
    }

    public byte[] getSault(byte le) throws Exception {
        return reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_GET_SAULT, (byte) 0x00, (byte) 0x00, le)).getData();
    }

    // KeyChain apdu
    public void resetKeyChain(byte[] data) throws Exception {
        reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_RESET_KEYCHAIN, (byte) 0x00, (byte) 0x00,
                data));
    }

    public byte[] getNumberOfKeys(byte[] data, byte le) throws Exception {
        return reader.sendAPDU(new CAPDU(WALLET_APPLET_CLA, INS_GET_NUMBER_OF_KEYS, (byte) 0x00, (byte) 0x00,
                data, le)).getData();
    }

    public byte[] getIndexAndLenOfKeyInKeyChain(byte[] data, byte le) throws Exception{
        return reader.sendAPDU(new CAPDU(
                WALLET_APPLET_CLA,
                INS_GET_KEY_INDEX_IN_STORAGE_AND_LEN,
                (byte) 0x00, (byte) 0x00,
                data,
                le)).getData();
    }

    public void checkAvailableVolForNewKey(byte[] data) throws Exception {
        reader.sendAPDU(new CAPDU(
                WALLET_APPLET_CLA,
                INS_CHECK_AVAILABLE_VOL_FOR_NEW_KEY,
                0x00, 0x00,
                data));
    }

    public void initiateChangeOfKey(byte[] data) throws Exception {
        reader.sendAPDU(new CAPDU(
                WALLET_APPLET_CLA,
                INS_INITIATE_CHANGE_OF_KEY,
                (byte) 0x00, (byte) 0x00,
                data));
    }

    public byte[] getFreeSize(byte[] data, byte le) throws Exception {
        return reader.sendAPDU(new CAPDU(
                WALLET_APPLET_CLA,
                INS_GET_FREE_STORAGE_SIZE,
                (byte) 0x00, (byte) 0x00,
                data, le)).getData();
    }

    public byte[] getOccupiedSize(byte[] data, byte le) throws Exception {
        return reader.sendAPDU(new CAPDU(
                WALLET_APPLET_CLA,
                INS_GET_OCCUPIED_STORAGE_SIZE,
                (byte) 0x00, (byte) 0x00,
                data, le)).getData();
    }

    public void checkKeyHmacConsistency(byte[] data) throws  Exception {
        reader.sendAPDU(new CAPDU(
                WALLET_APPLET_CLA,
                INS_CHECK_KEY_HMAC_CONSISTENCY,
                (byte) 0x00, (byte) 0x00,
                data));
    }


    public byte[] getHmac(byte[] data, byte le) throws  Exception {
        return reader.sendAPDU(new CAPDU(
                WALLET_APPLET_CLA,
                INS_GET_HMAC,
                (byte) 0x00, (byte) 0x00,
                data,
                le)).getData();
    }

    public byte[] initiateDeleteOfKey(byte[] data, byte le) throws Exception {
        return reader.sendAPDU(new CAPDU(
                WALLET_APPLET_CLA,
                INS_INITIATE_DELETE_KEY,
                (byte) 0x00, (byte) 0x00,
                data,
                le)).getData();
    }

    public byte[] getDeleteKeyChunkNumOfPackets(byte[] data, byte le) throws Exception {
        return reader.sendAPDU(new CAPDU(
                WALLET_APPLET_CLA,
                INS_GET_DELETE_KEY_CHUNK_NUM_OF_PACKETS,
                (byte) 0x00, (byte) 0x00,
                data,
                le)).getData();
    }

    public byte[] getDeleteKeyChunkCounter(byte[] data, byte le) throws Exception {
        return reader.sendAPDU(new CAPDU(
                WALLET_APPLET_CLA,
                INS_GET_DELETE_KEY_CHUNK_COUNTER,
                (byte) 0x00, (byte) 0x00,
                data,
                le)).getData();
    }

    public byte[] deleteKeyChunk(byte[] data, byte le) throws Exception {
        return reader.sendAPDU(new CAPDU(
                WALLET_APPLET_CLA,
                INS_DELETE_KEY_CHUNK,
                (byte) 0x00, (byte) 0x00,
                data,
                le)).getData();
    }

    public byte[] deleteKeyRecord(byte[] data, byte le) throws Exception {
        return reader.sendAPDU(new CAPDU(
                WALLET_APPLET_CLA,
                INS_DELETE_KEY_RECORD,
                (byte) 0x00, (byte) 0x00,
                data,
                le)).getData();
    }

    public byte[] getDeleteKeyRecordNumOfPackets(byte[] data, byte le) throws Exception {
        return reader.sendAPDU(new CAPDU(
                WALLET_APPLET_CLA,
                INS_GET_DELETE_KEY_RECORD_NUM_OF_PACKETS,
                (byte) 0x00, (byte) 0x00,
                data,
                le)).getData();
    }

    public byte[] getDeleteKeyRecordCounter(byte[] data, byte le) throws Exception {
        return reader.sendAPDU(new CAPDU(
                WALLET_APPLET_CLA,
                INS_GET_DELETE_KEY_RECORD_COUNTER,
                (byte) 0x00, (byte) 0x00,
                data,
                le)).getData();
    }


    public void addKeyChunk(byte p1, byte[] data) throws Exception {
        reader.sendAPDU(new CAPDU(
                WALLET_APPLET_CLA,
                INS_ADD_KEY_CHUNK,
                p1, 0x00,
                data));
    }

    public void changeKeyChunk(byte p1, byte[] data) throws Exception {
        reader.sendAPDU(new CAPDU(
                WALLET_APPLET_CLA,
                INS_CHANGE_KEY_CHUNK,
                p1, 0x00,
                data));
    }

    public void sendKeyChunk(byte p1, byte ins, byte[] data) throws Exception {
        if (ins == INS_CHANGE_KEY_CHUNK || ins == INS_ADD_KEY_CHUNK){
            reader.sendAPDU(new CAPDU(
                WALLET_APPLET_CLA,
                ins,
                p1, 0x00,
                data));
        }
        else throw new Exception("Bad instruction!");
    }

    public void sendKeyChunk(byte p1, byte ins, byte[] data, byte le) throws Exception {
        if (ins == INS_CHANGE_KEY_CHUNK || ins == INS_ADD_KEY_CHUNK){
            reader.sendAPDU(new CAPDU(
                    WALLET_APPLET_CLA,
                    ins,
                    p1, (byte)0x00,
                    data,
                    le));
        }
        else throw new Exception("Bad instruction!");
    }

    public byte[] getKeyChunk(byte[] data, byte le) throws Exception {
        return reader.sendAPDU(new CAPDU(
                WALLET_APPLET_CLA,
                INS_GET_KEY_CHUNK,
                (byte) 0x00, (byte) 0x00,
                data,
                le)).getData();
    }
}
