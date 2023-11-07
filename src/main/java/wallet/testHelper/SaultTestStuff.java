package wallet.testHelper;

import org.junit.Test;
import wallet.common.ByteArrayHelper;
import wallet.tonWalletApi.WalletHostAPI;

import java.util.HashSet;
import java.util.Set;

import static junit.framework.TestCase.assertTrue;
import static wallet.smartcard.WalletAppletConstants.PIN;

public class SaultTestStuff {
    public  static final int NUM_OF_ITERATIONS = 100;

    private Set<String> saulSet = new HashSet<>();

    private WalletHostAPI walletHostAPI;

    public SaultTestStuff(WalletHostAPI walletHostAPI) {
        this.walletHostAPI = walletHostAPI;
    }

    public void checkSaultRandomness() throws Exception {
        for(int i = 0; i < NUM_OF_ITERATIONS; i++) {
            byte[] sault = walletHostAPI.getSault();
            System.out.println("sault = " + ByteArrayHelper.hex(sault));
            saulSet.add(ByteArrayHelper.hex(sault));
            walletHostAPI.verifyPin(PIN);
        }
        System.out.println("saulSet.size() = " + saulSet.size());
        assertTrue(saulSet.size() == NUM_OF_ITERATIONS);
    }

    public void checkSaultProtocol() throws Exception {
        for(int i = 0; i < NUM_OF_ITERATIONS; i++) {
            byte[] sault =  walletHostAPI.getSault();
            System.out.println("sault = " + ByteArrayHelper.hex(sault));
            saulSet.add(ByteArrayHelper.hex(sault));
        }
        assertTrue(saulSet.size() == 1);
    }
}
