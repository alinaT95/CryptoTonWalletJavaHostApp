package wallet;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import wallet.common.ByteArrayHelper;
import wallet.testHelper.RecoveryDataTestHelper;
import wallet.tonWalletApi.WalletHostAPI;

import java.security.MessageDigest;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static wallet.common.ByteArrayHelper.bConcat;
import static wallet.common.ByteArrayHelper.bSub;
import static wallet.common.ByteArrayHelper.hex;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.pcscWrapper.helpers.ErrorCodes.*;
import static wallet.smartcard.utils.HmacHelper.computeMac;

public class RecoveryDataTest extends CardTwoFactorAuthorizationTest {
    public static final int NUM_OF_ITERATIONS =  100;
    private Random random = RecoveryDataTestHelper.random;
    private RecoveryDataTestHelper recoveryDataTestHelper = new RecoveryDataTestHelper(walletHostAPI);

    @Before
    public void runAuthorization() throws Exception {
        cardTwoFactorAuthorizationHelper.runAuthorization();
    }

    @Test
    public void testReset() throws Exception {
        recoveryDataTestHelper.testReset();
    }

    @Test
    public void testAddAndGetRecoveryData() throws Exception {
        recoveryDataTestHelper.testAddAndGetRecoveryData();
    }

    @Test
    public void testWrongLengthForAddRecoveryDataPart() throws Exception {
        WalletHostAPI.getWalletCardReaderWrapper().resetRecoveryData();
        int DATA_PORTION_MAX_SIZE = 252;

        short len = RECOVERY_DATA_MAX_SIZE + 1;
        byte[] recoveryData = new byte[len];
        random.nextBytes(recoveryData);

        int numberOfPackets = recoveryData.length / DATA_PORTION_MAX_SIZE;
        System.out.println(numberOfPackets);
        for (int j = 0; j < numberOfPackets; j++) {
            System.out.println("packet " + j);
            byte[] chunk = bSub(recoveryData, j * DATA_PORTION_MAX_SIZE, DATA_PORTION_MAX_SIZE);
            byte p1 = j == 0 ? (byte) 0x00 : (byte) 0x01;
            WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart(p1, chunk);
        }

        try {
            int tailLen = recoveryData.length % DATA_PORTION_MAX_SIZE;

            if (tailLen > 0) {
                byte[] chunk = bSub(recoveryData, numberOfPackets * DATA_PORTION_MAX_SIZE, tailLen);
                byte p1 = numberOfPackets == 0 ? (byte) 0x00 : (byte) 0x01;
                WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart(p1, chunk);
            }
            assertTrue(false);
        } catch (Exception e) {
            //e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
        }
    }

    @Test
    public void testWrongLengthForAddRecoveryDataPart2() throws Exception {
        for (int len = 0 ; len <= 255; len++) {
            if (len == SHA_HASH_SIZE)
                continue;
            System.out.println("len = " + len);
            byte[] hash = new byte[len];
            random.nextBytes(hash);
            try{
                WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart((byte) 0x02, hash);
                assertTrue(false);
            }
            catch (Exception e) {
                //e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
    }

    @Test
    public void testIncorrectHash() throws Exception {
        WalletHostAPI.getWalletCardReaderWrapper().resetRecoveryData();
        int DATA_PORTION_MAX_SIZE = 252;
        for (int i = 0 ; i < NUM_OF_ITERATIONS; i++) {
            System.out.println("Iter#" + i);
            short len =  (short) ThreadLocalRandom.current().nextInt(1,  RECOVERY_DATA_MAX_SIZE + 1);
            byte[] recoveryData = new byte[len];
            random.nextBytes(recoveryData);

            int numberOfPackets = recoveryData.length / DATA_PORTION_MAX_SIZE;
            System.out.println(numberOfPackets);
            for (int j = 0; j < numberOfPackets ; j++) {
                System.out.println("packet " + j);
                byte[] chunk = bSub(recoveryData, j * DATA_PORTION_MAX_SIZE, DATA_PORTION_MAX_SIZE);
                byte p1 = j == 0 ? (byte)0x00 : (byte)0x01;
                WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart(p1, chunk);
            }

            int tailLen = recoveryData.length % DATA_PORTION_MAX_SIZE;

            if(tailLen > 0) {
                byte[] chunk =  bSub(recoveryData, numberOfPackets * DATA_PORTION_MAX_SIZE, tailLen);
                byte p1 = numberOfPackets == 0 ? (byte)0x00 : (byte)0x01;
                WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart(p1, chunk);
            }

            byte[] hash = new byte[SHA_HASH_SIZE];
            random.nextBytes(hash);

            try{
                WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart((byte) 0x02, hash);
                assertTrue(false);
            }
            catch (Exception e) {
                //e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INTEGRITY_OF_RECOVERY_DATA_CORRUPTED)));
            }

        }
    }

    @Test
    public void testLostPacket() throws Exception {
        MessageDigest digest  = MessageDigest.getInstance("SHA-256");
        WalletHostAPI.getWalletCardReaderWrapper().resetRecoveryData();
        int DATA_PORTION_MAX_SIZE = 252;
        for (int i = 0 ; i < NUM_OF_ITERATIONS; i++) {
            System.out.println("Iter#" + i);
            short len = 1024;  //(short) ThreadLocalRandom.current().nextInt(1,  RECOVERY_DATA_MAX_SIZE + 1);
            byte[] recoveryData = new byte[len];
            random.nextBytes(recoveryData);

            int numberOfPackets = recoveryData.length / DATA_PORTION_MAX_SIZE;
            System.out.println(numberOfPackets);
            int k = random.nextInt(numberOfPackets);
            for (int j = 0; j < numberOfPackets ; j++) {
                System.out.println("packet " + j);
                if (j == k)  continue;
                byte[] chunk = bSub(recoveryData, j * DATA_PORTION_MAX_SIZE, DATA_PORTION_MAX_SIZE);

                byte p1 = j == 0 ? (byte)0x00 : (byte)0x01;
                WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart(p1, chunk);
            }

            int tailLen = recoveryData.length % DATA_PORTION_MAX_SIZE;

            if(tailLen > 0) {
                byte[] chunk =  bSub(recoveryData, numberOfPackets * DATA_PORTION_MAX_SIZE, tailLen);
                byte p1 = numberOfPackets == 0 ? (byte)0x00 : (byte)0x01;
                WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart(p1, chunk);
            }

            byte[] hash = digest.digest(recoveryData);

            try{
                WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart((byte) 0x02, hash);
                assertTrue(false);
            }
            catch (Exception e) {
                //e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INTEGRITY_OF_RECOVERY_DATA_CORRUPTED)));
            }
        }
    }

    @Test
    public void testLostLastPacket() throws Exception {
        MessageDigest digest  = MessageDigest.getInstance("SHA-256");
        WalletHostAPI.getWalletCardReaderWrapper().resetRecoveryData();
        int DATA_PORTION_MAX_SIZE = 252;
        for (int i = 0 ; i < NUM_OF_ITERATIONS; i++) {
            System.out.println("Iter#" + i);
            short len = 920;  //(short) ThreadLocalRandom.current().nextInt(1,  RECOVERY_DATA_MAX_SIZE + 1);
            byte[] recoveryData = new byte[len];
            random.nextBytes(recoveryData);

            int numberOfPackets = recoveryData.length / DATA_PORTION_MAX_SIZE;
            System.out.println(numberOfPackets);
            int k = random.nextInt(numberOfPackets);
            for (int j = 0; j < numberOfPackets ; j++) {
                System.out.println("packet " + j);
                byte[] chunk = bSub(recoveryData, j * DATA_PORTION_MAX_SIZE, DATA_PORTION_MAX_SIZE);
                byte p1 = j == 0 ? (byte)0x00 : (byte)0x01;
                WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart(p1, chunk);
            }

            byte[] hash = digest.digest(recoveryData);

            try{
                WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart((byte) 0x02, hash);
                assertTrue(false);
            }
            catch (Exception e) {
                //e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INTEGRITY_OF_RECOVERY_DATA_CORRUPTED)));
            }
        }
    }

    @Test
    public void testSpoilPacket() throws Exception {
        MessageDigest digest  = MessageDigest.getInstance("SHA-256");
        WalletHostAPI.getWalletCardReaderWrapper().resetRecoveryData();
        int DATA_PORTION_MAX_SIZE = 252;
        for (int i = 0 ; i < NUM_OF_ITERATIONS; i++) {
            System.out.println("Iter#" + i);
            short len = 1024;  //(short) ThreadLocalRandom.current().nextInt(1,  RECOVERY_DATA_MAX_SIZE + 1);
            byte[] recoveryData = new byte[len];
            random.nextBytes(recoveryData);

            int numberOfPackets = recoveryData.length / DATA_PORTION_MAX_SIZE;
            System.out.println(numberOfPackets);
            int k = random.nextInt(numberOfPackets);
            for (int j = 0; j < numberOfPackets ; j++) {
                System.out.println("packet " + j);
                byte[] chunk;
                if (j == k)  {
                    chunk = new byte[DATA_PORTION_MAX_SIZE];
                    random.nextBytes(chunk);
                }
                else {
                    chunk = bSub(recoveryData, j * DATA_PORTION_MAX_SIZE, DATA_PORTION_MAX_SIZE);
                }
                byte p1 = j == 0 ? (byte)0x00 : (byte)0x01;
                WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart(p1, chunk);
            }

            int tailLen = recoveryData.length % DATA_PORTION_MAX_SIZE;

            if(tailLen > 0) {
                byte[] chunk =  bSub(recoveryData, numberOfPackets * DATA_PORTION_MAX_SIZE, tailLen);
                byte p1 = numberOfPackets == 0 ? (byte)0x00 : (byte)0x01;
                WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart(p1, chunk);
            }

            byte[] hash = digest.digest(recoveryData);

            try{
                WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart((byte) 0x02, hash);
                assertTrue(false);
            }
            catch (Exception e) {
                //e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INTEGRITY_OF_RECOVERY_DATA_CORRUPTED)));
            }
        }
    }

    @Test
    public void testSpoilLastPacket() throws Exception {
        MessageDigest digest  = MessageDigest.getInstance("SHA-256");
        WalletHostAPI.getWalletCardReaderWrapper().resetRecoveryData();
        int DATA_PORTION_MAX_SIZE = 252;
        for (int i = 0 ; i < NUM_OF_ITERATIONS; i++) {
            System.out.println("Iter#" + i);
            short len = 890;  //(short) ThreadLocalRandom.current().nextInt(1,  RECOVERY_DATA_MAX_SIZE + 1);
            byte[] recoveryData = new byte[len];
            random.nextBytes(recoveryData);

            int numberOfPackets = recoveryData.length / DATA_PORTION_MAX_SIZE;
            System.out.println(numberOfPackets);
            int k = random.nextInt(numberOfPackets);
            for (int j = 0; j < numberOfPackets ; j++) {
                System.out.println("packet " + j);
                byte[] chunk = bSub(recoveryData, j * DATA_PORTION_MAX_SIZE, DATA_PORTION_MAX_SIZE);
                byte p1 = j == 0 ? (byte)0x00 : (byte)0x01;
                WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart(p1, chunk);
            }

            int tailLen = recoveryData.length % DATA_PORTION_MAX_SIZE;

            if(tailLen > 0) {
                byte[]  chunk = new byte[tailLen];
                random.nextBytes(chunk);
                byte p1 = numberOfPackets == 0 ? (byte)0x00 : (byte)0x01;
                WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart(p1, chunk);
            }

            byte[] hash = digest.digest(recoveryData);

            try{
                WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart((byte) 0x02, hash);
                assertTrue(false);
            }
            catch (Exception e) {
                //e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INTEGRITY_OF_RECOVERY_DATA_CORRUPTED)));
            }
        }
    }

    @Test
    public void testRecoveryDataExists() throws Exception {
        WalletHostAPI.getWalletCardReaderWrapper().resetRecoveryData();
        recoveryDataTestHelper.testAddAndGetRecoveryDataButNotReset(250);
        try{
            WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart((byte)0x00, new byte[200]);
            assertTrue(false);
        }
        catch (Exception e) {
            //e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_RECOVERY_DATA_ALREADY_EXISTS)));
        }

        try{
            WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart((byte)0x01, new byte[200]);
            assertTrue(false);
        }
        catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_RECOVERY_DATA_ALREADY_EXISTS)));
        }

        try{
            WalletHostAPI.getWalletCardReaderWrapper().addRecoveryDataPart((byte)0x02, new byte[200]);
            assertTrue(false);
        }
        catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_RECOVERY_DATA_ALREADY_EXISTS)));
        }
    }

    @Test
    public void testResetRecoveryDataSetAndIsRecoveryDataSet() throws Exception {
        for (int i = 0 ; i < NUM_OF_ITERATIONS; i++) {
            System.out.println("Iter#" + i);
            WalletHostAPI.getWalletCardReaderWrapper().resetRecoveryData();
            byte[] res = WalletHostAPI.getWalletCardReaderWrapper().isRecoveryDataSet();
            assertEquals(res.length, 1);
            assertTrue(res[0] == 0);
        }
    }

    @Test
    public void testWrongLengthIncorrectLeForIsRecoveryDataSet() throws Exception {
        for (int le = 0 ; le < 256; le++) {
            if (le == 0x01)
                continue;
            System.out.println("Le = " + le);
            try{
                WalletHostAPI.getWalletCardReaderWrapper().isRecoveryDataSet(le);
                assertTrue(false);
            }
            catch (Exception e) {
                //e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
    }

    @Test
    public void testRecoveryDataDoesNotExistForGetRecoveryDataHash() throws Exception {
        WalletHostAPI.getWalletCardReaderWrapper().resetRecoveryData();
        try{
            WalletHostAPI.getWalletCardReaderWrapper().getRecoveryDataHash(SHA_HASH_SIZE);
            assertTrue(false);
        }
        catch (Exception e) {
            //e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_RECOVERY_DATA_IS_NOT_SET)));
        }
    }

    @Test
    public void testWrongLengthIncorrectLeForGetRecoveryDataHash() throws Exception {
        WalletHostAPI.getWalletCardReaderWrapper().resetRecoveryData();
        recoveryDataTestHelper.testAddAndGetRecoveryDataButNotReset(250);
        for (int le = 0 ; le < 256; le++) {
            if (le == SHA_HASH_SIZE)
                continue;
            System.out.println("Le = " + le);
            try{
                WalletHostAPI.getWalletCardReaderWrapper().getRecoveryDataHash(le);
                assertTrue(false);
            }
            catch (Exception e) {
                //e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
    }

    @Test
    public void testRecoveryDataDoesNotExistForGetRecoveryDataLen() throws Exception {
        WalletHostAPI.getWalletCardReaderWrapper().resetRecoveryData();
        try{
            WalletHostAPI.getWalletCardReaderWrapper().getRecoveryDataLen();
            assertTrue(false);
        }
        catch (Exception e) {
            //e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_RECOVERY_DATA_IS_NOT_SET)));
        }
    }

    @Test
    public void testWrongLengthIncorrectLeForGetRecoveryDataLen() throws Exception {
        WalletHostAPI.getWalletCardReaderWrapper().resetRecoveryData();
        recoveryDataTestHelper.testAddAndGetRecoveryDataButNotReset(250);
        for (int le = 0 ; le < 256; le++) {
            if (le == 0x02)
                continue;
            System.out.println("Le = " + le);
            try{
                WalletHostAPI.getWalletCardReaderWrapper().getRecoveryDataLen(le);
                assertTrue(false);
            }
            catch (Exception e) {
                //e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
    }

    @Test
    public void testRecoveryDataDoesNotExistForGetRecoveryDataPart() throws Exception {
        WalletHostAPI.getWalletCardReaderWrapper().resetRecoveryData();
        try{
            byte[] data = new byte[2];
            random.nextBytes(data);
            WalletHostAPI.getWalletCardReaderWrapper().getRecoveryDataPart(data, (byte) 0x01);
            assertTrue(false);
        }
        catch (Exception e) {
            //e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_RECOVERY_DATA_IS_NOT_SET)));
        }
    }

    @Test
    public void testWrongLengthIncorrectLeForGetRecoveryDataPart() throws Exception {
        WalletHostAPI.getWalletCardReaderWrapper().resetRecoveryData();
        recoveryDataTestHelper.testAddAndGetRecoveryDataButNotReset(250);
        for (int len = 0 ; len <= 255; len++) {
            if (len == 0x02)
                continue;
            System.out.println("len = " + len);
            try {
                byte[] data = new byte[len];
                random.nextBytes(data);
                WalletHostAPI.getWalletCardReaderWrapper().getRecoveryDataPart(data, (byte) 0x01);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRONG_LENGTH)));
            }
        }
    }

    @Test
    public void testNegativeStartPosForGetRecoveryDataPart() throws Exception {
        WalletHostAPI.getWalletCardReaderWrapper().resetRecoveryData();
        recoveryDataTestHelper.testAddAndGetRecoveryDataButNotReset(250);
        for (int i = 0 ; i <= NUM_OF_ITERATIONS; i++) {
            System.out.println("Iter#" + i);
            short negativeStartPos = (short)(-1 * (short) (random.nextInt(Short.MAX_VALUE)));
            System.out.println("negativeStartPos = " + negativeStartPos);
            byte[] bytes = new byte[2];
            ByteArrayHelper. setShort(bytes, (short) 0, negativeStartPos );
            try {
                WalletHostAPI.getWalletCardReaderWrapper().getRecoveryDataPart(bytes, (byte) 0x01);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_START_POS_OR_LE)));
            }
        }
    }

    @Test
    public void testTooBigStartPosForGetRecoveryDataPart() throws Exception {
        WalletHostAPI.getWalletCardReaderWrapper().resetRecoveryData();
        recoveryDataTestHelper.testAddAndGetRecoveryDataButNotReset(250);
        for (int i = 0 ; i <= NUM_OF_ITERATIONS; i++) {
            System.out.println("Iter#" + i);
            short bigStartPos =  (short) ThreadLocalRandom.current().nextInt(RECOVERY_DATA_MAX_SIZE + 1, Short.MAX_VALUE + 1);
            System.out.println("bigStartPos = " + bigStartPos);
            byte[] bytes = new byte[2];
            ByteArrayHelper. setShort(bytes, (short) 0, bigStartPos);
            try {
                WalletHostAPI.getWalletCardReaderWrapper().getRecoveryDataPart(bytes, (byte) 0x01);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_START_POS_OR_LE)));
            }
        }
    }

    @Test
    public void testTooBigStartPosPlusLeForGetRecoveryDataPart() throws Exception {
        WalletHostAPI.getWalletCardReaderWrapper().resetRecoveryData();
        recoveryDataTestHelper.testAddAndGetRecoveryDataButNotReset(250);
        for (int i = 0 ; i <= NUM_OF_ITERATIONS; i++) {
            System.out.println("Iter#" + i);
            int le =  (byte) ThreadLocalRandom.current().nextInt(255);
            System.out.println("le = " + (short)(le & 0xFF));
            short startPos =  (short) (RECOVERY_DATA_MAX_SIZE - (short)(le & 0xFF) + 1);
            System.out.println("startPos = " + startPos);
            byte[] bytes = new byte[2];
            ByteArrayHelper. setShort(bytes, (short) 0, startPos);
            try {
                WalletHostAPI.getWalletCardReaderWrapper().getRecoveryDataPart(bytes, (byte) le);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_START_POS_OR_LE)));
            }
        }
    }

    @Test
    // byte le = 0x00 is interpreted by applet like short value = 256
    public void tesTooBigStartPosPlusLeForGetRecoveryDataPart2() throws Exception {
        WalletHostAPI.getWalletCardReaderWrapper().resetRecoveryData();
        recoveryDataTestHelper.testAddAndGetRecoveryDataButNotReset(250);
        for (int i = 0 ; i <= 255; i++) {
            System.out.println("Iter#" + i);
            short startPos =  (short) (RECOVERY_DATA_MAX_SIZE - i);
            System.out.println("startPos = " + startPos);
            byte[] bytes = new byte[2];
            ByteArrayHelper. setShort(bytes, (short) 0, startPos);
            try {
                WalletHostAPI.getWalletCardReaderWrapper().getRecoveryDataPart(bytes, (byte) 0x00);
                assertTrue(false);
            }
            catch (Exception e) {
                e.printStackTrace();
                Assert.assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_START_POS_OR_LE)));
            }
        }
    }




}



