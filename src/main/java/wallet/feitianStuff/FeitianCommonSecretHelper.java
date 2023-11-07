package wallet.feitianStuff;

import au.com.bytecode.opencsv.CSVReader;
import au.com.bytecode.opencsv.CSVWriter;
import wallet.common.ByteArrayHelper;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class FeitianCommonSecretHelper {
    public static final int NUM_OF_SAMPLES = 100;

    // (P1, H1, SN, B1, H2, IV, CS, H3)
    private List<String[]> fullTuples;
    // (B1, SN, CS)
    private List<String[]> feitianTuples = new ArrayList<>();
    // (P1, H1, SN, B1, H2, IV, CS, ECS, H3), H3 - now hash of ECS, NOT of CS as previously!!!
    private List<String[]> newFullTuples = new ArrayList<>();
    // (B1, SN, ECS) , ECS -- encrypted CS
    private List<String[]> newFeitianTuples = new ArrayList<>();

    private static MessageDigest digest;

    public static void main(String[] args){
        FeitianCommonSecretHelper feitianCommonSecretHelper = new FeitianCommonSecretHelper();
        feitianCommonSecretHelper.readTuples();
        feitianCommonSecretHelper.makeNewTuples();
        feitianCommonSecretHelper.verifyTuples();
    }

    private void verifyTuples() {
        fullTuples.clear();
        newFullTuples.clear();
        newFeitianTuples.clear();

        System.out.println("\n\n Read data from csv: \n\n");
        try(CSVReader readerFull = new CSVReader(new FileReader("fullTuplesForTonCard240320.csv"));
            CSVReader readerNewFull = new CSVReader(new FileReader("freshFullTuplesForTonCard131020.csv"));
            CSVReader readerNewFeitian = new CSVReader(new FileReader("freshFeitianTuplesForTonCard131020.csv"))
            ) {
            List<String[]> fullTuples = readerFull.readAll();
            List<String[]> newFullTuples = readerNewFull.readAll();
            List<String[]> newFeitianTuples = readerNewFeitian.readAll();

            System.out.println(fullTuples.size());

            for(int tupleNumber = 0; tupleNumber < NUM_OF_SAMPLES; tupleNumber++) {
                System.out.println("tupleNumber#" + tupleNumber);

                assertTrue(fullTuples.get(tupleNumber)[0].equals(newFullTuples.get(tupleNumber)[0]));
                assertTrue(fullTuples.get(tupleNumber)[1].equals(newFullTuples.get(tupleNumber)[1]));
                assertTrue(fullTuples.get(tupleNumber)[2].equals(newFullTuples.get(tupleNumber)[2]));
                assertTrue(fullTuples.get(tupleNumber)[3].equals(newFullTuples.get(tupleNumber)[3]));
                assertTrue(fullTuples.get(tupleNumber)[4].equals(newFullTuples.get(tupleNumber)[4]));
                assertTrue(fullTuples.get(tupleNumber)[5].equals(newFullTuples.get(tupleNumber)[5]));
                assertTrue(fullTuples.get(tupleNumber)[6].equals(newFullTuples.get(tupleNumber)[6]));
                assertTrue(!fullTuples.get(tupleNumber)[7].equals(newFullTuples.get(tupleNumber)[7]));

                assertTrue(newFullTuples.get(tupleNumber)[3].equals(newFeitianTuples.get(tupleNumber)[0]));
                assertTrue(newFullTuples.get(tupleNumber)[2].equals(newFeitianTuples.get(tupleNumber)[1]));
                assertTrue(newFullTuples.get(tupleNumber)[7].equals(newFeitianTuples.get(tupleNumber)[2]));


                IvParameterSpec ivSpec  = new IvParameterSpec(ByteArrayHelper.bytes(newFullTuples.get(tupleNumber)[5]));
                SecretKeySpec skeySpec = new SecretKeySpec(ByteArrayHelper.bSub(ByteArrayHelper.bytes(newFullTuples.get(tupleNumber)[1]), 0, 16), "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
                byte[] encryptedCommonSecretBytes = cipher.doFinal(ByteArrayHelper.bytes(newFullTuples.get(tupleNumber)[6]));
                String encryptedCommonSecret = ByteArrayHelper.hex(encryptedCommonSecretBytes);
                assertTrue(encryptedCommonSecret.equals(newFullTuples.get(tupleNumber)[7]));
                assertTrue(encryptedCommonSecret.equals(newFeitianTuples.get(tupleNumber)[2]));


                byte[] hashOfEncryptedCommonSecretBytes = digest.digest(encryptedCommonSecretBytes);
                String hashOfEncryptedCommonSecret = ByteArrayHelper.hex(hashOfEncryptedCommonSecretBytes);
                assertTrue(hashOfEncryptedCommonSecret.equals(newFullTuples.get(tupleNumber)[8]));
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }

    private void makeNewTuples() {
        try {
            digest = MessageDigest.getInstance("SHA-256");
            for(int tupleNumber = 0; tupleNumber < NUM_OF_SAMPLES; tupleNumber++) {
                System.out.println("tupleNumber#" + tupleNumber);

                String password = fullTuples.get(tupleNumber)[0];
                System.out.println("password = " +  password);

                String passwordHash = fullTuples.get(tupleNumber)[1];
                System.out.println("password hash = " + passwordHash);

                String sn = fullTuples.get(tupleNumber)[2];
                System.out.println("serial number = " + sn);

                String encryptedPassword = fullTuples.get(tupleNumber)[3];
                System.out.println("encryptedPassword = " +  encryptedPassword);

                String hashOfEncryptedPassword = fullTuples.get(tupleNumber)[4];
                System.out.println("hashOfEncryptedPassword = " +  hashOfEncryptedPassword);

                String iv = fullTuples.get(tupleNumber)[5];
                System.out.println("IV = " +  iv);

                String commonSecret = fullTuples.get(tupleNumber)[6];
                System.out.println("commonSecret = " +  commonSecret);



                IvParameterSpec ivSpec  = new IvParameterSpec(ByteArrayHelper.bytes(iv));
                SecretKeySpec skeySpec = new SecretKeySpec(ByteArrayHelper.bSub(ByteArrayHelper.bytes(passwordHash), 0, 16), "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
                byte[] encryptedCommonSecretBytes = cipher.doFinal(ByteArrayHelper.bytes(commonSecret));
                String encryptedCommonSecret = ByteArrayHelper.hex(encryptedCommonSecretBytes);
                System.out.println("encryptedCommonSecret = " +  encryptedCommonSecret);

                byte[] hashOfEncryptedCommonSecretBytes = digest.digest(encryptedCommonSecretBytes);
                String hashOfEncryptedCommonSecret = ByteArrayHelper.hex(hashOfEncryptedCommonSecretBytes);
                System.out.println("hashOfEncryptedCommonSecret = " +  hashOfEncryptedCommonSecret);


                System.out.println("------------------------------------------- \n");

                // (P1, H1, SN, B1, H2, IV, CS, ECS, H3)
                String[] newFullTuple = new String[]{password, passwordHash, sn, encryptedPassword, hashOfEncryptedPassword, iv, commonSecret, encryptedCommonSecret, hashOfEncryptedCommonSecret};

                // (B1, SN, ECS)
                String[] newFeitianTuple = new String[]{encryptedPassword, sn, encryptedCommonSecret};

                newFullTuples.add(newFullTuple);
                newFeitianTuples.add(newFeitianTuple);

            }

            writeIntoCsv(newFullTuples, "freshFullTuplesForTonCard131020.csv");
            writeIntoCsv(newFeitianTuples, "freshFeitianTuplesForTonCard131020.csv");
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void writeIntoCsv(List<String[]> tuples, String path) {
        try(CSVWriter writer = new CSVWriter(new FileWriter(path))) {
            writer.writeAll(tuples);
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }

    private void readTuples() {
        try(CSVReader readerFull = new CSVReader(new FileReader("fullTuplesForTonCard240320.csv"))) {
            fullTuples = readerFull.readAll();
            System.out.println(fullTuples.size());
        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }

}
