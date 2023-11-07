package wallet.testHelper;

import wallet.tonWalletApi.WalletHostAPI;

import static junit.framework.TestCase.assertTrue;
import static wallet.smartcard.WalletAppletConstants.*;
import static wallet.smartcard.WalletAppletConstants.DATA_FOR_SIGNING_MAX_SIZE_FOR_CASE_WITH_PATH;

public class TonWalletAppletTest {

    public static void main(String[] args) {
        try {
            WalletHostAPI walletHostAPI = new WalletHostAPI();
            CardConnector cardConnector = new CardConnector(walletHostAPI);
            cardConnector.connect();

            CardTwoFactorAuthorizationHelper cardTwoFactorAuthorizationHelper = new CardTwoFactorAuthorizationHelper(walletHostAPI);
            cardTwoFactorAuthorizationHelper.runAuthorization();

            System.out.println("Start SaultTestStuff...");

            SaultTestStuff saultTestStuff = new SaultTestStuff(walletHostAPI);
            saultTestStuff.checkSaultProtocol();
            saultTestStuff.checkSaultRandomness();

            System.out.println("Start PublicKeyTestStuff...");

            PublicKeyTestStuff publicKeyTestStuff = new PublicKeyTestStuff(walletHostAPI);
            publicKeyTestStuff.testGetPubicKey();
            publicKeyTestStuff.testGetPubicKeyForDefaultPath();

            System.out.println("Start Ed25519SignWithDefaultPathTestStuff...");

            Ed25519SignWithDefaultPathTestStuff ed25519SignWithDefaultPathTestStuff = new Ed25519SignWithDefaultPathTestStuff(walletHostAPI);
            ed25519SignWithDefaultPathTestStuff.testSignWithDefaultPathVsSignShortForGivenDataLength(TRANSACTION_HASH_SIZE);
            ed25519SignWithDefaultPathTestStuff.testSignWithDefaultPathForGivenDataLength(TRANSACTION_HASH_SIZE);
            ed25519SignWithDefaultPathTestStuff.testSignWithDefaultPathForGivenDataLength(DATA_FOR_SIGNING_MAX_SIZE);
            ed25519SignWithDefaultPathTestStuff.testSignWithDefaultPathForGivenDataLength(DATA_FOR_SIGNING_MIN_LEN);

            System.out.println("Start Ed25519TestStuff...");

            Ed25519SignTestStuff ed25519SignTestStuff = new Ed25519SignTestStuff(walletHostAPI);
            String keyIndex = "2147483642";
            ed25519SignTestStuff.testSignWithDefaultPathForGivenDataLength(TRANSACTION_HASH_SIZE, keyIndex);
            ed25519SignTestStuff.testSignWithDefaultPathForGivenDataLength(DATA_FOR_SIGNING_MAX_SIZE_FOR_CASE_WITH_PATH, keyIndex);
            ed25519SignTestStuff.testSignWithDefaultPathForGivenDataLength(DATA_FOR_SIGNING_MIN_LEN, keyIndex);

            ed25519SignTestStuff.testSignShortForLen32ForRandomHdIndexes();
           // ed25519SignTestStuff.testSignShortForAllLengthForRandomHdIndexes();

//            for (int len = DATA_FOR_SIGNING_MIN_LEN; len <= DATA_FOR_SIGNING_MAX_SIZE_FOR_CASE_WITH_PATH; len++) {
//                System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
//                ed25519SignTestStuff.testSignWithDefaultPathForGivenDataLength(len, keyIndex);
//                System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~n\n\n");
//            }



//            for(int len = DATA_FOR_SIGNING_MIN_LEN; len <= DATA_FOR_SIGNING_MAX_SIZE; len++){
//                System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
//                ed25519SignWithDefaultPathTestStuff.testSignWithDefaultPathForGivenDataLength(len);
//                System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
//            }

        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}
