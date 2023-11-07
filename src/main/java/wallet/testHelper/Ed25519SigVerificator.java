package wallet.testHelper;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;

public class Ed25519SigVerificator {
    private byte[] publicKey;

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public boolean verify(byte[] msg, byte[] sig){
        try {
            EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
            Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
            EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(publicKey, spec);
            PublicKey vKey = new EdDSAPublicKey(pubKey);
            sgr.initVerify(vKey);
            sgr.setParameter(EdDSAEngine.ONE_SHOT_MODE);

            sgr.update(msg);

            return sgr.verify(sig);
        }
        catch (Exception e){
            e.printStackTrace();
            return false;
        }
    }
}
