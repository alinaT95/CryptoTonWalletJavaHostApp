package wallet.feitianStuff;

import au.com.bytecode.opencsv.CSVWriter;
import wallet.common.ByteArrayHelper;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;

import static junit.framework.TestCase.assertTrue;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.WalletAppletConstants.SHA_HASH_SIZE;
import static wallet.smartcard.utils.HmacHelper.computeMac;

public class FeitianGenerator {
    public static final String FULL_TUPLES_PATH = "fullTuplesForTonCard.csv";
    public static final String FEITIAN_TUPLES_PATH = "feitianTuplesForTonCard.csv";
    public static final int NUM_OF_SAMPLES = 100;
    private static final int SN_LEN = 24;
    private static byte[] password = new byte[PASSWORD_SIZE];
    private static  byte[] passwordHash  = new byte[SHA_HASH_SIZE];
    private static byte[] commonSecret = new byte[COMMON_SECRET_SIZE];
    private static byte[] hashOfCommonSecret = new byte[SHA_HASH_SIZE];
    private static byte[] encryptedPassword = new byte[PASSWORD_SIZE];
    private static byte[] hashOfEncryptedPassword = new byte[SHA_HASH_SIZE];
    private static byte[] iv = new byte[IV_SIZE];
    private static byte[] keyForMac = new byte[HMAC_SHA_SIG_SIZE];
    private static Random random = new Random();
    private static MessageDigest digest;
    private static int tuplesCounter = 0;

   // private static BigInteger modulusDecimal = new BigInteger("1000000000000000000000000");

    // (P1, H1, SN, B1, H2, IV, CS, H3)
    private static List<String[]> fullTuples = new ArrayList<>();

    // (B1, SN, CS)
    private static List<String[]> feitianTuples = new ArrayList<>();

    public static void main(String[] args){
        try {
            digest = MessageDigest.getInstance("SHA-256");
            int i = 0;
            while (tuplesCounter < NUM_OF_SAMPLES) {
                System.out.println("Iter = " + i);
                System.out.println("tuplesCounter = " + tuplesCounter);
                random.nextBytes(password);
                String passwordInHex = ByteArrayHelper.hex(password);
                System.out.println("Password = " + passwordInHex);

                random.nextBytes(iv);
                String ivInHex = ByteArrayHelper.hex(iv);
                System.out.println("IV = " + ivInHex);

                random.nextBytes(commonSecret);
                String commonSecretInHex = ByteArrayHelper.hex(commonSecret);
                System.out.println("commonSecret = " + commonSecretInHex);

                passwordHash = digest.digest(password);
                String passwordHashInHex = ByteArrayHelper.hex(passwordHash);
                keyForMac = computeMac(passwordHash, commonSecret);
                System.out.println("key = " +  ByteArrayHelper.hex(keyForMac));

                String serialNumber = makeSn(passwordHash);

                IvParameterSpec ivSpec  = new IvParameterSpec(iv );
                SecretKeySpec skeySpec = new SecretKeySpec(ByteArrayHelper.bSub(passwordHash, 0, 16), "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
                encryptedPassword = cipher.doFinal(password);
                String encryptedPasswordInHex = ByteArrayHelper.hex(encryptedPassword);
                System.out.println("encryptedPassword = " +  encryptedPasswordInHex);

                hashOfEncryptedPassword = digest.digest(encryptedPassword);
                String encryptedPasswordHashInHex = ByteArrayHelper.hex(hashOfEncryptedPassword);
                System.out.println("hashOfEncryptedPassword = " +  encryptedPasswordHashInHex);

                hashOfCommonSecret = digest.digest(commonSecret);
                String hashOfCommonSecretInHex = ByteArrayHelper.hex(hashOfCommonSecret);
                System.out.println("hashOfCommonSecret = " +  hashOfCommonSecretInHex);

                System.out.println("------------------------------------------- \n");

                // (P1, H1, SN, B1, H2, IV, CS, H3)
                String[] newFullTuple = new String[]{passwordInHex, passwordHashInHex, serialNumber, encryptedPasswordInHex, encryptedPasswordHashInHex, ivInHex, commonSecretInHex, hashOfCommonSecretInHex};

                // (B1, SN, CS)
                String[] newFeitianTuple = new String[]{encryptedPasswordInHex, serialNumber, commonSecretInHex};

                if (!isCollision(newFullTuple)) {
                    fullTuples.add(newFullTuple);
                    feitianTuples.add(newFeitianTuple);
                    tuplesCounter++;
                }
                i++;

            }
            writeIntoCsv(fullTuples, FULL_TUPLES_PATH);
            writeIntoCsv(feitianTuples, FEITIAN_TUPLES_PATH);

           /* byte[] passwordHash = new byte[32];
            random.nextBytes(passwordHash);
            System.out.println(ByteArrayHelper.hex(passwordHash));
            BigInteger hashDecimal = new BigInteger(passwordHash);
            System.out.println(hashDecimal);
            System.out.println(ByteArrayHelper.hex(hashDecimal.toByteArray()));

            String modulus = "1000000000000000000000000";
            BigInteger modulusDecimal = new BigInteger(modulus);
            BigInteger residue = hashDecimal.mod(modulusDecimal);
                System.out.println(residue);
            System.out.println(modulusDecimal);*/




        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String makeSn(byte[] hash) throws Exception{
        BigInteger hashDecimal = new BigInteger(hash);

        System.out.println("passwordHash = " +  ByteArrayHelper.hex(hash));
        String hashDecimalStr = hashDecimal.compareTo(BigInteger.ZERO) == 1 ? hashDecimal.toString() : hashDecimal.toString().substring(1);
        String serialNumber;
        if (hashDecimalStr.length() >= SN_LEN) {
            serialNumber = hashDecimalStr.substring(0, SN_LEN);
        }
        else {
            serialNumber = hashDecimalStr + new String(new char[SN_LEN - hashDecimalStr.length()]).replace("\0", "0");
        }
        if (serialNumber.length() != SN_LEN) throw new Exception("bad sn!");
        System.out.println("serialNumber = " +  serialNumber);
        return serialNumber;
    }

    // (P1, H1, SN, B1, H2, IV, CS, H3)
    private static boolean isCollision(String[] newFullTuple) throws Exception{
        if (newFullTuple.length != 8) throw new Exception("bad tuple!");
        for (int i = 0 ; i < 8; i++) {
            for (String[] tuple : fullTuples) {
                if (tuple[i].length() != newFullTuple[i].length()) throw  new Exception("bad length!");
                boolean isCollision = tuple[i].equals(newFullTuple[i]);
                if (isCollision) return true;
            }
        }
        return false;
    }

    private static void writeIntoCsv(List<String[]> tuples, String path) {
        try(CSVWriter writer = new CSVWriter(new FileWriter(path))) {
            writer.writeAll(tuples);
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }

}
