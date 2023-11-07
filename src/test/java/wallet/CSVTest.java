package wallet;

import au.com.bytecode.opencsv.CSVReader;
import au.com.bytecode.opencsv.CSVWriter;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import wallet.common.ByteArrayHelper;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static wallet.feitianStuff.FeitianGenerator.*;

public class CSVTest {

    public static MessageDigest digest;

    @Before
    public void before() throws Exception{
        digest = MessageDigest.getInstance("SHA-256");
    }

    @Test
    // (P1, H1, SN, B1, H2, IV, CS, H3)
    // (B1, SN, CS)
    public void checkCsvTuples() throws Exception {
        try(CSVReader readerFull = new CSVReader(new FileReader(FULL_TUPLES_PATH)); CSVReader readerFeitian = new CSVReader(new FileReader(FEITIAN_TUPLES_PATH))) {
            List<String[]> fullTuples = readerFull.readAll();
            List<String[]> feitianTuples = readerFeitian.readAll();
            System.out.println(fullTuples.size());
            assertTrue(fullTuples.size() == feitianTuples.size());
            assertTrue(fullTuples.size() == NUM_OF_SAMPLES);

            for (int i = 0 ; i < 8; i++) {
                Set<String> set = new HashSet<>();
                for (String[] tuple : fullTuples) {
                    set.add(tuple[i]);
                }
                assertTrue(set.size() == NUM_OF_SAMPLES);
            }

            for (int i = 0 ; i < 3; i++) {
                Set<String> set = new HashSet<>();
                for (String[] tuple : feitianTuples) {
                    set.add(tuple[i]);
                }
                assertTrue(set.size() == NUM_OF_SAMPLES);
            }

            for (int i = 0; i < NUM_OF_SAMPLES; i++) {
                String[] fullTuple = fullTuples.get(i);
                String[] feitianTuple = feitianTuples.get(i);
                assertTrue(feitianTuple[0].equals(fullTuple[3]));
                assertTrue(feitianTuple[1].equals(fullTuple[2]));
                assertTrue(feitianTuple[2].equals(fullTuple[6]));
            }

            for (int i = 0; i < NUM_OF_SAMPLES; i++) {
                String[] fullTuple = fullTuples.get(i);
                byte[] p1 = ByteArrayHelper.bytes(fullTuple[0]);
                byte[] passwordHash = digest.digest(p1);

                byte[] h1 = ByteArrayHelper.bytes(fullTuple[1]);
                Assert.assertArrayEquals(passwordHash, h1);

                String sn = makeSn(h1);
                assertTrue(sn.equals(fullTuple[2]));


                byte[] iv = ByteArrayHelper.bytes(fullTuple[5]);
                IvParameterSpec ivSpec  = new IvParameterSpec(iv);
                SecretKeySpec skeySpec = new SecretKeySpec(/*key.getBytes("UTF-8")*/ ByteArrayHelper.bSub(passwordHash, 0, 16), "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);

                byte[] encryptedPassword = cipher.doFinal(p1);
                assertTrue(fullTuple[3].equals(ByteArrayHelper.hex(encryptedPassword)));

                byte[] h2 = digest.digest(encryptedPassword);
                assertTrue(fullTuple[4].equals(ByteArrayHelper.hex(h2)));

                byte[] h3 = digest.digest(ByteArrayHelper.bytes(fullTuple[6]));
                assertTrue(fullTuple[7].equals(ByteArrayHelper.hex(h3)));
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }

    }
}
