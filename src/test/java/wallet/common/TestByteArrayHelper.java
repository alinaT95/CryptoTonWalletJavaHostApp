package wallet.common;

import junit.framework.TestCase;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import wallet.common.ByteArrayHelper;

import java.util.Arrays;

public class TestByteArrayHelper{
    final private static Logger log = LoggerFactory.getLogger(TestByteArrayHelper.class);


    /*
        Hex
     */

    @Test
    public void testHex() {
        Assert.assertEquals("42AD", ByteArrayHelper.hex(new byte[]{0x42, (byte) 0xAD}));
    }
    @Test(expected = IllegalArgumentException.class) public void testHexEx1() {ByteArrayHelper.hex(null);}


    /*
        Bytes
     */
    @Test
    public void testBytes() {
        Assert.assertArrayEquals(new byte[]{(byte) 0xFA, (byte) 0xCE, (byte) 0x8D}, ByteArrayHelper.bytes("FACE8D"));
        Assert.assertArrayEquals(new byte[]{(byte) 0xFA, (byte) 0xCE, (byte) 0x8D}, ByteArrayHelper.bytes("FacE8D"));
        Assert.assertArrayEquals(new byte[]{(byte) 0xFF, (byte) 0xAA, (byte) 0xCC}, ByteArrayHelper.bytes(0xFFAACC));
        Assert.assertArrayEquals(new byte[]{(byte) 0xBE}, ByteArrayHelper.bytes(0xBE));
    }
    @Test(expected = IllegalArgumentException.class) public void testBytesEx1() {ByteArrayHelper.bytes(null);}
    @Test(expected = IllegalArgumentException.class) public void testBytesEx2() {ByteArrayHelper.bytes("012");}
    @Test(expected = IllegalArgumentException.class) public void testBytesEx3() {ByteArrayHelper.bytes("suc");}

    /*
        Equals
     */
    @Test
    public void testEquals() {
        Assert.assertTrue(ByteArrayHelper.bEquals(new byte[]{0x42, (byte) 0xAD}, new byte[]{0x42, (byte) 0xAD}));
    }

    @Test
    public void testNotEquals() {
        Assert.assertFalse(ByteArrayHelper.bEquals(new byte[]{0x42, (byte) 0xAD}, new byte[]{0x42}));
        Assert.assertFalse(ByteArrayHelper.bEquals(new byte[]{}, new byte[]{0x42}));
        Assert.assertFalse(ByteArrayHelper.bEquals(new byte[]{0x42, (byte) 0xAD}, new byte[]{0x42}));
    }

    @Test(expected = IllegalArgumentException.class) public void testEqualsException1() {ByteArrayHelper.bEquals(null, new byte[]{0x42});}
    @Test(expected = IllegalArgumentException.class) public void testEqualsException2() {ByteArrayHelper.bEquals(new byte[]{0x42}, null);}
    @Test(expected = IllegalArgumentException.class) public void testEqualsException3() {ByteArrayHelper.bEquals(null, null);}


    /*
        Copy
     */
    @Test
    public void testCopy() {
        Assert.assertArrayEquals(new byte[]{0x42, 0x13}, ByteArrayHelper.bCopy(new byte[]{0x42, 0x13}));
    }

    @Test(expected = IllegalArgumentException.class) public void testCopyEx() {ByteArrayHelper.bCopy(null);}

    /*
        Left
     */
    @Test
    public void testLeft() {
        Assert.assertArrayEquals(new byte[]{0x42}, ByteArrayHelper.bLeft(new byte[]{0x42,0x13}, 1));
    }

    @Test(expected = IllegalArgumentException.class) public void testLeftEx1() {ByteArrayHelper.bLeft(null, 1);}
    @Test(expected = IllegalArgumentException.class) public void testLeftEx2() {ByteArrayHelper.bLeft(new byte[]{0x42}, -1);}
    @Test(expected = IllegalArgumentException.class) public void testLeftEx3() {ByteArrayHelper.bLeft(new byte[]{0x42}, 2);}


    /*
        Right
     */
    @Test
    public void testRight() {
        Assert.assertArrayEquals(new byte[]{0x13}, ByteArrayHelper.bRight(new byte[]{0x42, 0x13}, 1));
    }

    @Test(expected = IllegalArgumentException.class) public void testRightEx1() {ByteArrayHelper.bRight(null, 1);}
    @Test(expected = IllegalArgumentException.class) public void testRightEx2() {ByteArrayHelper.bRight(new byte[]{0x42}, -1);}
    @Test(expected = IllegalArgumentException.class) public void testRightEx3() {ByteArrayHelper.bRight(new byte[]{0x42}, 2);}


    /*
        Sub
     */
    @Test
    public void testSub() {
        Assert.assertArrayEquals(new byte[]{0x02,0x03}, ByteArrayHelper.bSub(new byte[]{0x01,0x02,0x03,0x04}, 1,2));
        Assert.assertArrayEquals(new byte[]{0x04}, ByteArrayHelper.bSub(new byte[]{0x01,0x02,0x03,0x04}, 3,1));
        Assert.assertArrayEquals(new byte[]{}, ByteArrayHelper.bSub(new byte[]{0x01, 0x02, 0x03, 0x04}, 1, 0));
    }

    @Test(expected = IllegalArgumentException.class) public void testSubEx1() {ByteArrayHelper.bSub(null, 1,2);}
    @Test(expected = IllegalArgumentException.class) public void testSubEx2() {ByteArrayHelper.bSub(new byte[]{}, -1,1);}
    @Test(expected = IllegalArgumentException.class) public void testSubEx3() {ByteArrayHelper.bSub(new byte[]{0x01}, 0, 2);}
    @Test(expected = IllegalArgumentException.class) public void testSubEx4() {ByteArrayHelper.bSub(new byte[]{0x01}, 0, -1);}

    @Test
    public void testAsciiToHex() {
        Assert.assertArrayEquals(new byte[]{0x6D,0x2F,0x34,0x34,0x27,0x2F,0x31,0x37,0x31,0x27,0x2F,0x30,0x27,0x2F,0x30,0x27,0x2F,0x30,0x27}, ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex("m/44'/171'/0'/0'/0'")) );
        //System.out.println("Arrays.toString(ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex(\"m/44'/171'/0'/0'/0'\")) ) = " + Arrays.toString(ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex("m/44'/171'/0'/0'/0'"))));
                
        //pathlist = ["6D2F3434272F313731272F30272F30272F3027"] # "m/44'/171'/0'/0'/0'"-ed25519 use

        Assert.assertArrayEquals(new byte[]{0x6D,0x2F,0x34,0x34,0x27,0x2F,0x31,0x37,0x31,0x27,0x2F,0x30,0x27,0x2F,0x30,0x2F,0x30}, ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex("m/44'/171'/0'/0/0")) );
        //pathlist = ["6D2F3434272F313731272F30272F302F30"] # "m/44'/171'/0'/0/0"

        //testHelper root
        //Assert.assertArrayEquals(new byte[]{,}, ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex("m/0'")) );
        //Assert.assertArrayEquals(new byte[]{,}, ByteArrayHelper.bytes(ByteArrayHelper.asciiToHex("m/44'/171'/0'")) );
    }


}
