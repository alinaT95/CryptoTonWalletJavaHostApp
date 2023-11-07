package wallet.smartcard.pcscWrapper.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static wallet.common.ByteArrayHelper.hex;

public class SessionKeys {

    final private static Logger log = LoggerFactory.getLogger(SessionKeys.class);

    public final byte[] encKey;
    public final byte[] macKey;
    public final byte[] decKey;


    public SessionKeys(byte[] encKey, byte[] macKey, byte[] decKey) {
        this.encKey = encKey;
        this.macKey = macKey;
        this.decKey = decKey;
    }

    public void toLog(){
        System.out.println("Session DEC: " + hex(this.decKey));
        System.out.println("Session ENC: " + hex(this.encKey));
        System.out.println("Session MAC: " + hex(this.macKey));
        System.out.println("-----------------------------------------");
    }

}
