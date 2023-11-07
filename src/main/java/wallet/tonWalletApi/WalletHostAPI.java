package wallet.tonWalletApi;

import au.com.bytecode.opencsv.CSVReader;
import wallet.common.ByteArrayHelper;
import wallet.smartcard.CardState;
import wallet.smartcard.CardStateWatcher;
import wallet.smartcard.INotifier;
import wallet.smartcard.readerWrappers.TonWalletCardReaderWrapper;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import java.io.*;
import java.security.MessageDigest;
import java.util.*;

import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.bSub;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.*;
import static wallet.smartcard.WalletAppletConstants.*;

import static wallet.smartcard.utils.HmacHelper.*;
import static wallet.smartcard.utils.StringHelper.extendStringByZeros;


/**
 * Created by Asus on 20.08.2019.
 */
public class WalletHostAPI {
    public static MessageDigest digest;

    private static CardStateWatcher cardStateWatcher;

    private static TonWalletCommandsApi tonWalletApi;

    private static CardState walletCardState;

    private byte[] serialNumber = new byte[SERIAL_NUMBER_SIZE];

    private byte[] encryptedCommonSecret = new byte[COMMON_SECRET_SIZE];

    private byte[] commonSecret = new byte[COMMON_SECRET_SIZE];

    private byte[] hashOfEncryptedCommonSecret = new byte[SHA_HASH_SIZE];

    private byte[] password = new byte[PASSWORD_SIZE];

    private byte[] encryptedPassword = new byte[PASSWORD_SIZE];

    private byte[] hashOfEncryptedPassword = new byte[SHA_HASH_SIZE];

    private byte[] iv = new byte[IV_SIZE];

    private byte[] key = new byte[HMAC_SHA_SIG_SIZE];

    private Random random = new Random();


    private int occupiedSizeCounter = 0;

    private Map<String, String> keyChainData = new LinkedHashMap<>();

    static {
        try{
            digest = MessageDigest.getInstance("SHA-256");
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static TonWalletCommandsApi getTonWalletApi() {
        return tonWalletApi;
    }

    public static TonWalletCardReaderWrapper getWalletCardReaderWrapper(){
        return tonWalletApi.getWalletCardReaderWrapper();
    }

    public void setOccupiedSizeCounter(int occupiedSizeCounter) {
        this.occupiedSizeCounter = occupiedSizeCounter;
    }

    public static CardState getWalletCardState() {
        return walletCardState;
    }

    private static void addCardsHandlers() {
        cardStateWatcher.onCardInserted(event -> {
            try {

                fillCardReaderAndCardState(event.cardChannel);

                if (tonWalletApi != null) {
                    System.out.println("Wallet Card is reading...");

                    if (walletCardState != CardState.EMPTY){
                        System.out.println("Wallet Applet is present on card...");
                    }
                    else{
                        System.out.println("Wallet Card is empty...");
                    }

                } else {
                    System.out.println("Card is not inserted!");
                }

                setCardReaderWrapperCurState();

            } catch (Throwable e1) {
                e1.printStackTrace();
                System.out.println("ERROR: " + e1.getMessage());
            }

            System.out.println("===============================================================");

        });

        cardStateWatcher.onCardRemoved(event -> {
            tonWalletApi = null;

            setCardReaderWrapperCurState();

            System.out.println("No card!");
            System.out.println("===============================================================");
        });

    }

    public static void refreshCardState() throws CardException {
        if (tonWalletApi != null)
            walletCardState = tonWalletApi.getWalletCardReaderWrapper().getAppletState(INSTANCE_AID);
    }

    private static void fillCardReaderAndCardState(CardChannel cardChannel) throws Exception {
        walletCardState = CardState.NOT_INSERTED;
        if (cardChannel != null) {
            tonWalletApi = new TonWalletCommandsApi(cardChannel);
            walletCardState = tonWalletApi.getWalletCardReaderWrapper().getAppletState(INSTANCE_AID);
        }
    }

    public static boolean getCardReaderWrapperCurState(){
        return tonWalletApi != null;
    }


    private static void setCardReaderWrapperCurState(){
        if (cardStateWatcher != null)
            cardStateWatcher.getCurState().setState(getCardReaderWrapperCurState());
    }

    public static void setAndStartCardsStateWatcher(INotifier notifier){
        cardStateWatcher = new CardStateWatcher("");
        cardStateWatcher.setNotifier(notifier);
        addCardsHandlers();
        cardStateWatcher.start();
    }


    public static CardStateWatcher getCardStateWatcher() {
        return cardStateWatcher;
    }

    public Map<String, String> getKeyChainData() {
        return keyChainData;
    }

    public int getOccupiedSizeCounter() {
        return occupiedSizeCounter;
    }

    public byte getAppletState() throws CardException {
        System.out.println("\n Getting applet state: ");
        return tonWalletApi.getAppInfo();
    }

    public byte[] getSault() throws Exception {
        System.out.println("Getting sault from card ...");
        return tonWalletApi.getSault();
    }

    // =================== PERSONALIZATION ===================
    public void finishPers() throws Exception {
        System.out.println("\n Finish personalization: ");
        tonWalletApi.finishPers();
    }

    public void setEncryptedPassword(byte[] encryptedPasswordBytes) throws Exception {
        System.out.println("\n Setting encrypted password for card authentication: ");
        tonWalletApi.setEncryptedPassword(encryptedPasswordBytes);
    }

    public void readPersonalizationStuffForAppletFromCsv(){
        System.out.println("\n\n Read data from csv: \n\n");
        try(CSVReader readerFull = new CSVReader(new FileReader("myTuple.csv")); CSVReader readerFeitian = new CSVReader(new FileReader("myTupleShort.csv"))) {
            List<String[]> fullTuples = readerFull.readAll();
            List<String[]> feitianTuples = readerFeitian.readAll();
            System.out.println(fullTuples.size());

            int tupleNumber = 0; //random.nextInt(fullTuples.size());
            System.out.println("tupleNumber = " + tupleNumber);

            password = ByteArrayHelper.bytes(fullTuples.get(tupleNumber)[0]);
            System.out.println("Password = " +  ByteArrayHelper.hex(password));

            iv = ByteArrayHelper.bytes(fullTuples.get(tupleNumber)[5]);
            System.out.println("IV = " +  ByteArrayHelper.hex(iv));

            commonSecret = ByteArrayHelper.bytes(fullTuples.get(tupleNumber)[6]);
            System.out.println("commonSecret = " +  ByteArrayHelper.hex(commonSecret));

            byte[] passwordHash = ByteArrayHelper.bytes(fullTuples.get(tupleNumber)[1]);
            System.out.println("passwordHash = " +  ByteArrayHelper.hex(passwordHash));

            key = computeMac(passwordHash, commonSecret);
            saveKey();

            System.out.println("key for hmac making  = " +  ByteArrayHelper.hex(key));

            encryptedPassword = ByteArrayHelper.bytes(feitianTuples.get(tupleNumber)[0]);
            System.out.println("encryptedPassword = " +  ByteArrayHelper.hex(encryptedPassword));
            assertTrue(fullTuples.get(tupleNumber)[3].equals(feitianTuples.get(tupleNumber)[0]));

            encryptedCommonSecret = ByteArrayHelper.bytes(feitianTuples.get(tupleNumber)[2]);
            System.out.println("encryptedCommonSecret = " +  ByteArrayHelper.hex(encryptedCommonSecret));
            assertTrue(fullTuples.get(tupleNumber)[7].equals(feitianTuples.get(tupleNumber)[2]));

            hashOfEncryptedPassword = ByteArrayHelper.bytes(fullTuples.get(tupleNumber)[4]);
            System.out.println("hashOfEncryptedPassword = " +  ByteArrayHelper.hex(hashOfEncryptedPassword));

            hashOfEncryptedCommonSecret = ByteArrayHelper.bytes(fullTuples.get(tupleNumber)[8]);
            System.out.println("hashOfEncryptedCommonSecret = " +  ByteArrayHelper.hex(hashOfEncryptedCommonSecret));

            serialNumber = ByteArrayHelper.bytes(extendStringByZeros(feitianTuples.get(tupleNumber)[1]));
            System.out.println("serialNumber = " +  ByteArrayHelper.hex(serialNumber));
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }


    // (P1, H1, SN, B1, H2, IV, CS, ECS, H3)
    // (B1, SN, ECS)
    public void readPersonalizationStuffForApplet(){
        try{
            System.out.println("\n\n Fill Personalization  data: \n\n");

            password = ByteArrayHelper.bytes("F4B072E1DF2DB7CF6CD0CD681EC5CD2D071458D278E6546763CBB4860F8082FE14418C8A8A55E2106CBC6CB1174F4BA6D827A26A2D205F99B7E00401DA4C15ACC943274B92258114B5E11C16DA64484034F93771547FBE60DA70E273E6BD64F8A4201A9913B386BCA55B6678CFD7E7E68A646A7543E9E439DD5B60B9615079FE");
            System.out.println("Password = " +  ByteArrayHelper.hex(password));

            iv = ByteArrayHelper.bytes("1A550F4B413D0E971C28293F9183EA8A");
            System.out.println("IV = " +  ByteArrayHelper.hex(iv));

            commonSecret = ByteArrayHelper.bytes("7256EFE7A77AFC7E9088266EF27A93CB01CD9432E0DB66D600745D506EE04AC4");
            System.out.println("commonSecret = " +  ByteArrayHelper.hex(commonSecret));

            byte[] passwordHash = ByteArrayHelper.bytes("6F83BBEF900614F609DDBBB0CC014CC1ED19A30A40E5E171C5734901B8047705");
            System.out.println("passwordHash = " +  ByteArrayHelper.hex(passwordHash));

            key = computeMac(passwordHash, commonSecret);
            saveKey();

            System.out.println("key for hmac making  = " +  ByteArrayHelper.hex(key));

            encryptedPassword = ByteArrayHelper.bytes("7BF6D157F017189AE9904959878A851376BE01127582D675004790CFC194E6AC273D85F55B7050B08FC48F3142AA68974B9765D0799BB5804F6FD4A4BF38686D8E1AE548E60603D32DD85C57DADB146CDE4CFD30D0321DCD5A2B8010760E70A93E429FBC2A458FE84B63B35DB9902893E2C81CD53A2AA20E268A57D188F93D69");
            System.out.println("encryptedPassword = " +  ByteArrayHelper.hex(encryptedPassword));

            encryptedCommonSecret = ByteArrayHelper.bytes("71E872C73979904C17722CB2A5FA6B7A107DBA38924338F739A1C0E96D74BC33");
            System.out.println("encryptedCommonSecret = " +  ByteArrayHelper.hex(encryptedCommonSecret));

            hashOfEncryptedPassword = ByteArrayHelper.bytes("112716D2053C2828DC265B5DF14F85F203F8350DCB5774950901F3136108FA2C");
            System.out.println("hashOfEncryptedPassword = " +  ByteArrayHelper.hex(hashOfEncryptedPassword));

            hashOfEncryptedCommonSecret = ByteArrayHelper.bytes("71106ED2161D12E5E59FA7FF298930F0F4BB398171A712CB26D947A0DAF5F0EF");
            System.out.println("hashOfEncryptedCommonSecret = " +  ByteArrayHelper.hex(hashOfEncryptedCommonSecret));

            serialNumber = ByteArrayHelper.bytes(extendStringByZeros("504394802433901126813236"));
            System.out.println("serialNumber = " +  ByteArrayHelper.hex(serialNumber));

        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
    // (P1, H1, SN, B1, H2, IV, CS, ECS, H3)
    // (B1, SN, ECS)
    public void personlizeAppletFromCsv(){
        System.out.println("\n\n Personalization of wallet applet from csv: \n\n");
        try(CSVReader readerFull = new CSVReader(new FileReader("myTuple.csv")); CSVReader readerFeitian = new CSVReader(new FileReader("myTupleShort.csv"))) {
            List<String[]> fullTuples = readerFull.readAll();
            List<String[]> feitianTuples = readerFeitian.readAll();
            System.out.println(fullTuples.size());

            int tupleNumber = 0; //random.nextInt(fullTuples.size());
            System.out.println("tupleNumber = " + tupleNumber);

            password = ByteArrayHelper.bytes(fullTuples.get(tupleNumber)[0]);
            System.out.println("Password = " +  ByteArrayHelper.hex(password));

            iv = ByteArrayHelper.bytes(fullTuples.get(tupleNumber)[5]);
            System.out.println("IV = " +  ByteArrayHelper.hex(iv));

            commonSecret = ByteArrayHelper.bytes(fullTuples.get(tupleNumber)[6]);
            System.out.println("commonSecret = " +  ByteArrayHelper.hex(commonSecret));

            byte[] passwordHash = ByteArrayHelper.bytes(fullTuples.get(tupleNumber)[1]);
            System.out.println("passwordHash = " +  ByteArrayHelper.hex(passwordHash));

            key = computeMac(passwordHash, commonSecret);
            saveKey();

            System.out.println("key for hmac making  = " +  ByteArrayHelper.hex(key));

            encryptedPassword = ByteArrayHelper.bytes(feitianTuples.get(tupleNumber)[0]);
            System.out.println("encryptedPassword = " +  ByteArrayHelper.hex(encryptedPassword));
            assertTrue(fullTuples.get(tupleNumber)[3].equals(feitianTuples.get(tupleNumber)[0]));

            encryptedCommonSecret = ByteArrayHelper.bytes(feitianTuples.get(tupleNumber)[2]);
            System.out.println("encryptedCommonSecret = " +  ByteArrayHelper.hex(encryptedCommonSecret));
            assertTrue(fullTuples.get(tupleNumber)[7].equals(feitianTuples.get(tupleNumber)[2]));

            hashOfEncryptedPassword = ByteArrayHelper.bytes(fullTuples.get(tupleNumber)[4]);
            System.out.println("hashOfEncryptedPassword = " +  ByteArrayHelper.hex(hashOfEncryptedPassword));

            hashOfEncryptedCommonSecret = ByteArrayHelper.bytes(fullTuples.get(tupleNumber)[8]);
            System.out.println("hashOfEncryptedCommonSecret = " +  ByteArrayHelper.hex(hashOfEncryptedCommonSecret));

            serialNumber = ByteArrayHelper.bytes(extendStringByZeros(feitianTuples.get(tupleNumber)[1]));
            System.out.println("serialNumber = " +  ByteArrayHelper.hex(serialNumber));

            tonWalletApi.setEncryptedPassword(encryptedPassword);
            tonWalletApi.setEncryptedCommonSecret(encryptedCommonSecret);
            tonWalletApi.setSerialNumber(serialNumber);

            tonWalletApi.finishPers();

            System.out.println("\n Personalization finished \n\n");
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    // (P1, H1, SN, B1, H2, IV, CS, ECS, H3)
    // (B1, SN, ECS)
    public void personlizeAppletFromHardcodedData(){
        try{
            System.out.println("\n\n Personalization of wallet applet by test data: \n\n");

            password = ByteArrayHelper.bytes("F4B072E1DF2DB7CF6CD0CD681EC5CD2D071458D278E6546763CBB4860F8082FE14418C8A8A55E2106CBC6CB1174F4BA6D827A26A2D205F99B7E00401DA4C15ACC943274B92258114B5E11C16DA64484034F93771547FBE60DA70E273E6BD64F8A4201A9913B386BCA55B6678CFD7E7E68A646A7543E9E439DD5B60B9615079FE");
            System.out.println("Password = " +  ByteArrayHelper.hex(password));

            iv = ByteArrayHelper.bytes("1A550F4B413D0E971C28293F9183EA8A");
            System.out.println("IV = " +  ByteArrayHelper.hex(iv));

            commonSecret = ByteArrayHelper.bytes("7256EFE7A77AFC7E9088266EF27A93CB01CD9432E0DB66D600745D506EE04AC4");
            System.out.println("commonSecret = " +  ByteArrayHelper.hex(commonSecret));

            byte[] passwordHash = ByteArrayHelper.bytes("6F83BBEF900614F609DDBBB0CC014CC1ED19A30A40E5E171C5734901B8047705");
            System.out.println("passwordHash = " +  ByteArrayHelper.hex(passwordHash));

            key = computeMac(passwordHash, commonSecret);
            saveKey();

            System.out.println("key for hmac making  = " +  ByteArrayHelper.hex(key));

            encryptedPassword = ByteArrayHelper.bytes("7BF6D157F017189AE9904959878A851376BE01127582D675004790CFC194E6AC273D85F55B7050B08FC48F3142AA68974B9765D0799BB5804F6FD4A4BF38686D8E1AE548E60603D32DD85C57DADB146CDE4CFD30D0321DCD5A2B8010760E70A93E429FBC2A458FE84B63B35DB9902893E2C81CD53A2AA20E268A57D188F93D69");
            System.out.println("encryptedPassword = " +  ByteArrayHelper.hex(encryptedPassword));

            encryptedCommonSecret = ByteArrayHelper.bytes("71E872C73979904C17722CB2A5FA6B7A107DBA38924338F739A1C0E96D74BC33");
            System.out.println("encryptedCommonSecret = " +  ByteArrayHelper.hex(encryptedCommonSecret));

            hashOfEncryptedPassword = ByteArrayHelper.bytes("112716D2053C2828DC265B5DF14F85F203F8350DCB5774950901F3136108FA2C");
            System.out.println("hashOfEncryptedPassword = " +  ByteArrayHelper.hex(hashOfEncryptedPassword));

            hashOfEncryptedCommonSecret = ByteArrayHelper.bytes("71106ED2161D12E5E59FA7FF298930F0F4BB398171A712CB26D947A0DAF5F0EF");
            System.out.println("hashOfEncryptedCommonSecret = " +  ByteArrayHelper.hex(hashOfEncryptedCommonSecret));

            serialNumber = ByteArrayHelper.bytes(extendStringByZeros("504394802433901126813236"));
            System.out.println("serialNumber = " +  ByteArrayHelper.hex(serialNumber));

            tonWalletApi.setEncryptedPassword(encryptedPassword);
            tonWalletApi.setEncryptedCommonSecret(encryptedCommonSecret);
            tonWalletApi.setSerialNumber(serialNumber);

            tonWalletApi.finishPers();

            System.out.println("\n Personalization finished \n\n");
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

   /* public void personalizeApplet() throws  Exception {
        System.out.println("\n\n Personalization of wallet applet: \n\n");
        random.nextBytes(password);
        System.out.println("Password = " + ByteArrayHelper.hex(password));

        random.nextBytes(iv);
        System.out.println("IV = " + ByteArrayHelper.hex(iv));

        random.nextBytes(commonSecret);
        byte[] passwordHash = digest.digest(password);

        key = computeMac(passwordHash, commonSecret);
        saveKey();

        IvParameterSpec ivSpec = new IvParameterSpec(iv );
        SecretKeySpec skeySpec = new SecretKeySpec(ByteArrayHelper.bSub(passwordHash, 0, 16), "AES");

        System.out.println("key = " + ByteArrayHelper.hex(ByteArrayHelper.bSub(key, 0, 16)));

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);

        encryptedPassword = cipher.doFinal(password);

        System.out.println("encryptedPassword = " + ByteArrayHelper.hex(encryptedPassword));

        tonWalletApi.setEncryptedPassword(encryptedPassword);

        hashOfEncryptedPassword = digest.digest(encryptedPassword);

        System.out.println("hashOfEncryptedPassword = " + ByteArrayHelper.hex(hashOfEncryptedPassword));

        System.out.println("commonSecret = " + ByteArrayHelper.hex(commonSecret));

        encryptedCommonSecret = cipher.doFinal(commonSecret);

        System.out.println("encryptedCommonSecret = " + ByteArrayHelper.hex(encryptedCommonSecret));

        tonWalletApi.setEncryptedCommonSecret(encryptedCommonSecret);

        hashOfEncryptedCommonSecret = digest.digest(encryptedCommonSecret);

        System.out.println("hashOfEncryptedCommonSecret = " + ByteArrayHelper.hex(hashOfEncryptedCommonSecret));

        tonWalletApi.finishPers();

        System.out.println("\n Personalization finished \n\n");

    }*/

    private void saveKey() throws IOException{
        try (FileOutputStream stream = new FileOutputStream("key.txt")) {
            stream.write(key);
        }
    }

    public byte[] getHashOfEncryptedPassword() {
        return hashOfEncryptedPassword;
    }

    public byte[] getHashOfEncryptedCommonSecret() {
        return hashOfEncryptedCommonSecret;
    }

    public byte[] getSerialNumber() throws CardException {
        return serialNumber;
    }

    public void resetWalletAndGenerateSeed() throws CardException {
        System.out.println("\n Reset wallet and generate seed: ");
        tonWalletApi.getWalletCardReaderWrapper().selectCoinManager();
        tonWalletApi.getWalletCardReaderWrapper().resetWallet();
        tonWalletApi.getWalletCardReaderWrapper().generateSeed();
        tonWalletApi.getWalletCardReaderWrapper().getReader().selectAID(INSTANCE_AID);
    }

    //  ===================  Waite for authentication mode  ===================

    public byte[] getHashOfEncryptedPasswordFromCard() throws CardException {
        System.out.println("\n Check HashOfEncryptedPassword: ");
        byte[] hashFromCard = tonWalletApi.getHashOfEncryptedPassword();
        System.out.println("hashFromCard = " +  ByteArrayHelper.hex( hashFromCard));
        return  hashFromCard;
    }

    public byte[] getHashOfEncryptedCommonSecretFromCard() throws CardException {
        System.out.println("\n Check HashOfCommonSecret: ");
        byte[] hashFromCard = tonWalletApi.getHashOfEncryptedCommonSecret();
        System.out.println("hashFromCard = " +  ByteArrayHelper.hex( hashFromCard));
        return  hashFromCard;
    }

    public void verifyPassword() throws CardException {
        System.out.println("\n Verify password:");
        tonWalletApi.verifyPassword(password, iv);
    }

    public void verifyPassword(byte[] password, byte[] iv) throws CardException {
        tonWalletApi.verifyPassword(password, iv);
    }


    //=================== MAIN MODE ====================================================

    public byte[] getSerialNumberFromCard() throws CardException {
        System.out.println("\n getSerialNumber: ");
        byte[] serialNumber = tonWalletApi.getSerialNumber();
        System.out.println("serialNumber = " +  ByteArrayHelper.hex(serialNumber));
        return serialNumber;
    }

    public void resetRecoveryData() throws Exception{
        System.out.println("\n Reset recovery data in wallet applet: ");
        tonWalletApi.resetRecoveryData();
    }

    public int getRecoveryDataLen() throws Exception{
        System.out.println("\n Retrieving recovery data length from wallet applet: ");
        return tonWalletApi.getRecoveryDataLen();
    }

    public byte[] getRecoveryDataHash() throws Exception{
        System.out.println("\n Retrieving recovery data sha256 hash from wallet applet: ");
        return tonWalletApi.getRecoveryDataHash();
    }

    public boolean isRecoveryDataSet() throws Exception{
        System.out.println("\n Retrieving flag isRecoveryDataSet from wallet applet: ");
        return tonWalletApi.isRecoveryDataSet();
    }

    public byte[] getRecoveryData() throws Exception{
        System.out.println("\n Retrieving recovery data from wallet applet: ");
        return tonWalletApi.getRecoveryData();
    }

    public void addtRecoveryData(byte[] data) throws Exception{
        System.out.println("\n Adding recovery data from wallet applet: ");
        tonWalletApi.addRecoveryData(data);
    }

    public byte[] getPublicKey(byte [] indBytes) throws CardException{
        System.out.println("\n Retrieving Ed25519 pubic key from wallet applet: ");
        return tonWalletApi.getPublicKey(indBytes);
    }

    public byte[] getPublicKeyWithDefaultHDPath() throws CardException {
        System.out.println("\n Retrieving Ed25519 default pubic key from wallet applet: ");
        return tonWalletApi.getPublicKeyWithDefaultHDPath();
    }

    public void verifyPin(byte[] pinBytes) throws Exception {
        System.out.println("\n Checking PIN: ");
        tonWalletApi.verifyPin(pinBytes);
    }

    public byte[] signShortMessageWithDefaultPath(byte[] data) throws Exception{
        System.out.println("\n Retrieving Ed25519 signature for default HD path: ");
        return tonWalletApi.signShortMessageWithDefaultPath(data);
    }

    public byte[] signShortMessage(byte[] data, String ind) throws Exception{
        System.out.println("\n Retrieving Ed25519 signature: ");
        System.out.println("for ind  of HD path = " + ByteArrayHelper.asciiToHex(ind));
        byte [] indBytes = ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex(ind));
        return tonWalletApi.signShortMessage(data, indBytes);
    }

    //Keychain
    public void addKeyIntoKeyChain(byte[] keyBytes) throws Exception{
        System.out.println("\n Add new key into keychain: ");
        System.out.println("key to add = " + ByteArrayHelper.hex(keyBytes));
        byte[] mac = computeMac(keyBytes);
        System.out.println("mac to add = " + ByteArrayHelper.hex(mac));
        System.out.println("key size to add = " + keyBytes.length);
//        if (isHmacExistOnCard(mac)){
//            System.out.println("Key with such mac already exists! Skip it");
//            return;
//        }
        tonWalletApi.checkAvailableVolForNewKey((short) keyBytes.length);
        tonWalletApi.addKey(keyBytes);
        keyChainData.put(ByteArrayHelper.hex(mac), ByteArrayHelper.hex(keyBytes));
        occupiedSizeCounter += keyBytes.length;
    }

    public boolean isHmacExistOnCard(byte[] mac) throws Exception{
        boolean res = true;
        try {
            tonWalletApi.getIndexAndLenOfKeyInKeyChain(mac);
        }
        catch (Exception e) {
            if (e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_KEY_INDEX))) {
                res = false;
            }
        }
        System.out.println("Is hmac exists on card = " + res);
        return res;
    }

    public void checkKeyHmacConsistency(byte[] keyHmac) throws  Exception {
        System.out.println("\n checkKeyHmacConsistency: ");
        tonWalletApi.checkKeyHmacConsistency(keyHmac);
    }

    public void changeKeyInKeyChain(byte[] newKeyBytes, byte[] macBytesOfOldKey) throws Exception {
        System.out.println("\n Change key in keychain: ");
        String macOld = ByteArrayHelper.hex(macBytesOfOldKey);
        int lenOfOldKey = keyChainData.get(macOld).length() / 2;
        byte[] mac = computeMac(newKeyBytes);
        System.out.println("mac of key to change = " + macOld);
        System.out.println("key to change = " + keyChainData.get(macOld));
        System.out.println("key length to change = " + lenOfOldKey);
        System.out.println("new mac = " + ByteArrayHelper.hex(mac));
        System.out.println("new key = " + ByteArrayHelper.hex(newKeyBytes));

        byte[] data = tonWalletApi.getIndexAndLenOfKeyInKeyChain(macBytesOfOldKey);
        int indexIntStorage = ByteArrayHelper.makeShort(data, 0);
        int keyLen = ByteArrayHelper.makeShort(data,2);

        if(keyLen != newKeyBytes.length) {
            throw new IllegalArgumentException("Bad new key length!");
        }

        tonWalletApi.initiateChangeOfKey(bSub(data, 0, 2));
        tonWalletApi.changeKey(newKeyBytes);

        keyChainData.remove(macOld);
        keyChainData.put(ByteArrayHelper.hex(mac), ByteArrayHelper.hex(newKeyBytes));
    }

//    public int deleteKeyFromKeyChain(byte[] macBytes) throws Exception {
//        System.out.println("\n\n\n Delete key from keychain: ");
//        String mac = ByteArrayHelper.hex(macBytes);
//        int lenOfKey = keyChainData.get(mac).length() / 2;
//        System.out.println("mac to delete = " + mac);
//        System.out.println("key to delete = " + keyChainData.get(mac));
//        System.out.println("key length to delete = " + lenOfKey + "\n\n");
//
//        byte[] data = tonWalletApi.getIndexAndLenOfKeyInKeyChain(macBytes);
//
//        int numOfKeysInKeyChain = tonWalletApi.deleteKey(bSub(data, 0, 2));
//
//        keyChainData.remove(ByteArrayHelper.hex(macBytes));
//        occupiedSizeCounter = occupiedSizeCounter - lenOfKey;
//
//        return numOfKeysInKeyChain;
//    }

    public int deleteKeyFromKeyChain(byte[] macBytes) throws Exception {
        System.out.println("\n\n\n Delete key from keychain: ");
        String mac = ByteArrayHelper.hex(macBytes);
        int lenOfKey = keyChainData.get(mac).length() / 2;
        System.out.println("mac to delete = " + mac);
        System.out.println("key to delete = " + keyChainData.get(mac));
        System.out.println("key length to delete = " + lenOfKey + "\n\n");

        byte[] data = tonWalletApi.getIndexAndLenOfKeyInKeyChain(macBytes);
        byte[] index = bSub(data, 0, 2);
        int keyLenToDelete = tonWalletApi.initiateDeleteOfKey(index);

        int deleteKeyChunkIsDone = 0;
        while (deleteKeyChunkIsDone == 0) {
            deleteKeyChunkIsDone = tonWalletApi.deleteKeyChunk();
        }

        int deleteKeyRecordIsDone = 0;
        while (deleteKeyRecordIsDone == 0) {
            deleteKeyRecordIsDone = tonWalletApi.deleteKeyRecord();
        }

        int numOfKeysInKeyChain = tonWalletApi.getNumberOfKeys();

        keyChainData.remove(ByteArrayHelper.hex(macBytes));
        occupiedSizeCounter = occupiedSizeCounter - lenOfKey;

        return numOfKeysInKeyChain;
    }

    public int deleteKeyFromKeyChainWithoutPresteps(byte[] macBytes) throws Exception {
        String mac = ByteArrayHelper.hex(macBytes);
        int lenOfKey = keyChainData.get(mac).length() / 2;
        int deleteKeyChunkIsDone = 0;
        while (deleteKeyChunkIsDone == 0) {
            deleteKeyChunkIsDone = tonWalletApi.deleteKeyChunk();
        }
        int deleteKeyRecordIsDone = 0;
        while (deleteKeyRecordIsDone == 0) {
            deleteKeyRecordIsDone = tonWalletApi.deleteKeyRecord();
        }
        int numOfKeysInKeyChain = tonWalletApi.getNumberOfKeys();
        keyChainData.remove(ByteArrayHelper.hex(macBytes));
        occupiedSizeCounter = occupiedSizeCounter - lenOfKey;
        return numOfKeysInKeyChain;
    }

    public int deleteKeyFromKeyChainForBreakingConnectionTest(byte[] macBytes) throws Exception {
        String mac = ByteArrayHelper.hex(macBytes);
        int lenOfKey = keyChainData.get(mac).length() / 2;
        int deleteKeyChunkIsDone = 0;
        while (deleteKeyChunkIsDone == 0) {
            deleteKeyChunkIsDone = tonWalletApi.deleteKeyChunk();
            try {
                Thread.sleep(500);
            } catch (InterruptedException e1) {
            }
        }
        int deleteKeyRecordIsDone = 0;
        while (deleteKeyRecordIsDone == 0) {
            deleteKeyRecordIsDone = tonWalletApi.deleteKeyRecord();
            try {
                Thread.sleep(500);
            } catch (InterruptedException e1) {
            }
        }
        int numOfKeysInKeyChain = tonWalletApi.getNumberOfKeys();
        keyChainData.remove(ByteArrayHelper.hex(macBytes));
        occupiedSizeCounter = occupiedSizeCounter - lenOfKey;
        return numOfKeysInKeyChain;
    }

    public byte[] getKeyFromKeyChain(byte[] macBytes) throws Exception{
        System.out.println("\n Get key from keychain:");
        byte[] data = tonWalletApi.getIndexAndLenOfKeyInKeyChain(macBytes);
        int keyLen = ByteArrayHelper.makeShort( data, 2);
        byte[] keyFromCard = tonWalletApi.getKey(keyLen, bSub(data, 0, 2));
        String mac = ByteArrayHelper.hex(macBytes);
        System.out.println("mac = " + mac);
        System.out.println("key from keyChainData = " + keyChainData.get(mac));
        System.out.println("keyFromCard = " + ByteArrayHelper.hex(keyFromCard));
        System.out.println("key length = " + keyLen  + "\n\n\n");
        return keyFromCard;
    }

    public void resetKeyChain() throws Exception {
        System.out.println("\n Reset keychain:");
        tonWalletApi.resetKeyChain();
        keyChainData.clear();
        occupiedSizeCounter = 0;
    }

    public int getNumberOfKeys() throws Exception {
        System.out.println("\n Get number of keys in keychain:");
        return tonWalletApi.getNumberOfKeys();
    }

    public int getOccupiedStorageSize() throws Exception{
        System.out.println("\n Get occupied storage volume:");
        return tonWalletApi.getOccupiedStorageSize();
    }

    public int getFreeStorageSize() throws Exception{
        System.out.println("\n Get free storage volum:");
        return tonWalletApi.getFreeStorageSize();
    }

    public int getDeleteKeyChunkNumOfPackets() throws Exception{
        System.out.println("\n getDeleteKeyChunkNumOfPackets:");
        return tonWalletApi.getDeleteKeyChunkNumOfPackets();
    }

    public int getDeleteKeyRecordNumOfPackets() throws Exception{
        System.out.println("\n getDeleteKeyRecordNumOfPackets:");
        return tonWalletApi.getDeleteKeyRecordNumOfPackets();
    }

    public int getDeleteKeyChunkCounter() throws Exception{
        System.out.println("\n getDeleteKeyChunkCounter:");
        return tonWalletApi.getDeleteKeyChunkCounter();
    }

    public int getDeleteKeyRecordCounter() throws Exception{
        System.out.println("\n getDeleteKeyRecordCounter:");
        return tonWalletApi.getDeleteKeyRecordCounter();
    }

    public Map<String, Integer> getAllHmacsOfKeysFromCard() throws  Exception {
        System.out.println("\n Get hmacs of all keys stored in card keychain:");
        Map<String, Integer> hmacs = new HashMap<>();

        int numOfKeys = getNumberOfKeys();
        byte[] ind = new byte[2];
        for(short i = 0; i < numOfKeys; i++){
            ByteArrayHelper.setShort(ind, (short)0, i);
            byte data[] = tonWalletApi.getHmac(ind);
            byte mac[] = ByteArrayHelper.bSub(data, 0, HMAC_SHA_SIG_SIZE);
            int len = ByteArrayHelper.makeShort(data, HMAC_SHA_SIG_SIZE);
            hmacs.put(ByteArrayHelper.hex(mac), len);
        }
        return hmacs;
    }

    public void addLargeKeys() throws Exception {
        resetKeyChain();
        printBeforeAddInfo();
        int size = 8192;
        int numOfKeysForAdding = 3;
        byte[] key = new byte[size];
        for (int i = 0; i < numOfKeysForAdding; i++) {
            random.nextBytes(key);
            System.out.println("\n \n Iteration = " + i);
            addKeyIntoKeyChain(key);
        }
        printAfterAddInfo();
    }

    public void addKeys0() throws Exception {
        resetKeyChain();
        printBeforeAddInfo();
        int size = 30;
        int numOfKeysForAdding = 1023;
        byte[] key = new byte[size];
        for (int i = 0; i < numOfKeysForAdding; i++) {
            random.nextBytes(key);
            System.out.println("\n \n Iteration = " + i);
            addKeyIntoKeyChain(key);
        }
        printAfterAddInfo();
    }

    public void addKeys1() throws Exception {
        resetKeyChain();
        printBeforeAddInfo();

        int deg = random.nextInt(8);
        int size = (1 << deg) * 64;
        int numOfKeysForAdding = KEY_CHAIN_SIZE / size;

        if (numOfKeysForAdding > MAX_NUMBER_OF_KEYS_IN_KEYCHAIN) {
            throw new Exception("Number of keys is too big.");
        }

        byte[] key = new byte[size];
        for (int i = 0; i < numOfKeysForAdding; i++) {
            random.nextBytes(key);
            System.out.println("\n \n Iteration = " + i);
            addKeyIntoKeyChain(key);;
        }

        printAfterAddInfo();
    }

    public void addKeys2() throws Exception {
        resetKeyChain();
        printBeforeAddInfo();
        int i = 0;
        while (i < 30) {
            try {
                int deg = random.nextInt(14);
                if (deg <= 1) continue;
                int size = 1 << deg;
                byte[] key = new byte[size];
                random.nextBytes(key);
                System.out.println("\n \n Iteration = " + i);
                addKeyIntoKeyChain(key);
                i++;
            } catch (Exception e) {
                e.printStackTrace();
                break;
            }
        }
        printAfterAddInfo();
    }

    public void addKeys3() throws Exception{
        resetKeyChain();
        printBeforeAddInfo();
        int i = 0;
        while (i < 50){
            try {
                int size = random.nextInt(512) + 1;
                byte[] key = new byte[size];
                random.nextBytes(key);
                System.out.println("\n \n Iteration = " + i);
                addKeyIntoKeyChain(key);
                i++;
            }
            catch (Exception e) {
                e.printStackTrace();
                break;
            }
        }
        printAfterAddInfo();
    }

    public void addKeys4() throws Exception {
        resetKeyChain();
        printBeforeAddInfo();
        int i = 0;
        while (occupiedSizeCounter <= KEY_CHAIN_SIZE / 2){
            int size = random.nextInt(4096) + 1;
            byte[] key = new byte [size];
            random.nextBytes(key);
            System.out.println("\n \n Iteration = " + i);
            System.out.println("\n \n Key size = " + size);
            addKeyIntoKeyChain(key);
            i++;
        }
        printAfterAddInfo();
    }

    public void addKeys5() throws Exception {
        resetKeyChain();
        printBeforeAddInfo();
        int size = 1024; //random.nextInt(MAX_KEY_SIZE_IN_KEYCHAIN) + 1;
        byte[] key = new byte[size];
        random.nextBytes(key);
        addKeyIntoKeyChain(key);
        printAfterAddInfo();
    }

    public void addKeys6() throws Exception {
        resetKeyChain();
        printBeforeAddInfo();
        int size = KEY_CHAIN_SIZE / MAX_NUMBER_OF_KEYS_IN_KEYCHAIN;
        byte[] key = new byte[size];
        for (int i = 0; i < MAX_NUMBER_OF_KEYS_IN_KEYCHAIN; i++) {
            random.nextBytes(key);
            System.out.println("\n \n Iteration = " + i);
            addKeyIntoKeyChain(key);
        }
        printAfterAddInfo();
    }

    public void addKeys7() throws Exception {
        resetKeyChain();
        printBeforeAddInfo();
        int size = 8;
        byte[] key = new byte[size];
        for (int i = 0; i < MAX_NUMBER_OF_KEYS_IN_KEYCHAIN; i++) {
            random.nextBytes(key);
            System.out.println("\n \n Iteration = " + i);
            addKeyIntoKeyChain(key);
        }
        printAfterAddInfo();
    }

    public void addKeys9() throws Exception {
        resetKeyChain();
        printBeforeAddInfo();
        int size = 8000;
        byte[] key = new byte[size];
        for (int i = 0; i < 4; i++) {
            random.nextBytes(key);
            System.out.println("\n \n Iteration = " + i);
            addKeyIntoKeyChain(key);
        }
        printAfterAddInfo();
    }

    public void addKeys10() throws Exception {
        resetKeyChain();
        printBeforeAddInfo();
        int size = 5000;
        byte[] key = new byte[size];
        for (int i = 0; i < 6; i++) {
            random.nextBytes(key);
            System.out.println("\n \n Iteration = " + i);
            addKeyIntoKeyChain(key);
        }
        printAfterAddInfo();
    }

    public void addKeys11() throws Exception {
        resetKeyChain();
        printBeforeAddInfo();
        int size = 500;
        byte[] key = new byte[size];
        for (int i = 0; i < 10; i++) {
            random.nextBytes(key);
            System.out.println("\n \n Iteration = " + i);
            addKeyIntoKeyChain(key);
        }
        printAfterAddInfo();
    }


    private void printBeforeAddInfo() {
        System.out.println("\n\n ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        System.out.println("Start keys adding");
        System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ \n");
    }

    private void printAfterAddInfo() {
        System.out.println("\n OccupiedSize = " + occupiedSizeCounter + "\n");
        System.out.println("\n Number of keys = " +  keyChainData.size() + "\n");
        System.out.println("\n Finished adding keys.... \n");
        System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ \n\n");
    }

    public int getOccupiedSizeAccordingToKeyChainData() {
        int size = 0;
        for(String hmac : keyChainData.keySet()) {
            size += (short)(keyChainData.get(hmac).length() / 2);
        }
        return size;
    }

    public int getFreeSizeAccordingToKeyChainData(){
        return KEY_CHAIN_SIZE - getOccupiedSizeAccordingToKeyChainData();
    }


}
