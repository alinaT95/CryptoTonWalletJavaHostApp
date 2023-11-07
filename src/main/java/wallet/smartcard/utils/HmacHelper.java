package wallet.smartcard.utils;

import wallet.common.ByteArrayHelper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Random;

import static wallet.smartcard.WalletAppletConstants.HMAC_SHA_SIG_SIZE;
import static wallet.smartcard.WalletAppletConstants.KEY_PATH;

public class HmacHelper {
    private static byte[] key = new byte[HMAC_SHA_SIG_SIZE];

    private static boolean isCorrrectKey = true;

    private static Random random = new Random();

    public static boolean isIsCorrrectKey() {
        return isCorrrectKey;
    }

    public static void setIsCorrrectKey(boolean isCorrrectKey) {
        HmacHelper.isCorrrectKey = isCorrrectKey;
    }

    public static byte[] computeMac(byte[] key, byte[] data) throws  Exception{

        //System.out.println("key = " + ByteArrayHelper.hex(key));
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key, "HmacSHA256");
        sha256_HMAC.init(secret_key);
        //  System.out.println("data for hmac = " + ByteArrayHelper.hex(data));
        return sha256_HMAC.doFinal(data);
    }

    public static byte[] computeMac(byte[] data) throws  Exception{
        getKey();
      //  System.out.println("key = " + ByteArrayHelper.hex(key));
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key, "HmacSHA256");
        sha256_HMAC.init(secret_key);
      //  System.out.println("data for hmac = " + ByteArrayHelper.hex(data));
        return sha256_HMAC.doFinal(data);
    }

    private static void getKey() throws IOException {
        if (isCorrrectKey) {
            try (FileInputStream stream = new FileInputStream(KEY_PATH)) {
                stream.read(key);

            }
            catch (Exception e) {
                key = ByteArrayHelper.bytes("903BB7913C2332455B97606381BB0CDE09E91EAD137F2CAFF4F6ACC7E0D2E318");
            }
            System.out.println("KEY =" + ByteArrayHelper.hex(key));
        }
        else {
            random.nextBytes(key);
        }
    }
}
