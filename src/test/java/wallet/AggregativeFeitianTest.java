package wallet;

import org.junit.internal.TextListener;
import org.junit.runner.JUnitCore;
import org.junit.runner.Request;
import org.junit.runner.Result;

public class AggregativeFeitianTest {
    public static void main(String[] args) {
        JUnitCore junit = new JUnitCore();
        junit.addListener(new TextListener(System.out));
        try{
            String testType = args.length > 0 ? args[0] : "";
            if (testType.equals("keychain")) {
                System.out.println("\n--------------------------------------------");
                System.out.println("Start KeyChainGetTest");
                runTest(wallet.keychain.KeyChainGetTest.class, "testGettingAllKeysFromKeyChain");
                runTest(wallet.keychain.KeyChainGetTest.class, "testGettingRandomKeysFromKeyChain");
                runTest(wallet.keychain.KeyChainGetTest.class, "testGettingRandomLargeKeyFromKeyChain");

                System.out.println("\n--------------------------------------------");
                System.out.println("Start KeyChainDeleteLightWeightTest");
                System.out.println("--------------------------------------------\n");
                runTest(wallet.keychain.KeyChainDeleteLightWeightTest.class, "testDeletingAllKeysFromKeyChain");
                runTest(wallet.keychain.KeyChainDeleteLightWeightTest.class, "testDeletingAllKeysOfArbitraryLenFromKeyChain");
                runTest(wallet.keychain.KeyChainDeleteLightWeightTest.class, "testDeletingOneLargeFromKeyChain");
                runTest(wallet.keychain.KeyChainDeleteLightWeightTest.class, "testDeletingHalfOfKeysFromKeyChain");
                runTest(wallet.keychain.KeyChainDeleteLightWeightTest.class, "testDeletingAllKeysExceptOfOneFromKeyChain");
                runTest(wallet.keychain.DeleteKeyRecordPositiveTest.class, "testPositive");

                System.out.println("\n--------------------------------------------");
                System.out.println("Start KeyChainChangeLightWeightTest");
                System.out.println("--------------------------------------------\n");
                runTest(wallet.keychain.KeyChainChangeLightWeightTest.class, "testChangingHalfOfKeysFromKeyChain");
                runTest(wallet.keychain.KeyChainChangeLightWeightTest.class, "testChangingAllKeysExceptOfOneFromKeyChain");

            }
            else {
                System.out.println("\n--------------------------------------------");
                System.out.println("Recovery data handler testing");
                System.out.println("--------------------------------------------\n");
                runTest(wallet.RecoveryDataTest.class, "testReset");
                runTest(wallet.RecoveryDataTest.class, "testAddAndGetRecoveryData");
                runTest(wallet.RecoveryDataTest.class, "testWrongLengthForAddRecoveryDataPart");
                runTest(wallet.RecoveryDataTest.class, "testIncorrectHash");
                runTest(wallet.RecoveryDataTest.class, "testLostPacket");
                runTest(wallet.RecoveryDataTest.class, "testLostLastPacket");
                runTest(wallet.RecoveryDataTest.class, "testSpoilPacket");
                runTest(wallet.RecoveryDataTest.class, "testSpoilLastPacket");
                runTest(wallet.RecoveryDataTest.class, "testRecoveryDataExists");
                runTest(wallet.RecoveryDataTest.class, "testResetRecoveryDataSetAndIsRecoveryDataSet");
                runTest(wallet.RecoveryDataTest.class, "testTooBigStartPosPlusLeForGetRecoveryDataPart");
                runTest(wallet.RecoveryDataTest.class, "tesTooBigStartPosPlusLeForGetRecoveryDataPart2");
                runTest(wallet.RecoveryDataTest.class, "testTooBigStartPosForGetRecoveryDataPart");
                runTest(wallet.RecoveryDataTest.class, "testNegativeStartPosForGetRecoveryDataPart");
                runTest(wallet.RecoveryDataTest.class, "testWrongLengthIncorrectLeForGetRecoveryDataPart");
                runTest(wallet.RecoveryDataTest.class, "testRecoveryDataDoesNotExistForGetRecoveryDataPart");
                runTest(wallet.RecoveryDataTest.class, "testWrongLengthIncorrectLeForGetRecoveryDataLen");
                runTest(wallet.RecoveryDataTest.class, "testRecoveryDataDoesNotExistForGetRecoveryDataLen");
                runTest(wallet.RecoveryDataTest.class, "testWrongLengthIncorrectLeForGetRecoveryDataHash");
                runTest(wallet.RecoveryDataTest.class, "testRecoveryDataDoesNotExistForGetRecoveryDataHash");
                runTest(wallet.RecoveryDataTest.class, "testWrongLengthIncorrectLeForIsRecoveryDataSet");

                System.out.println("\n--------------------------------------------");
                System.out.println("Sault handler testing");
                System.out.println("--------------------------------------------\n");
                runTest(wallet.SaultHandlerTest.class, "checkSaultRandomness");
                runTest(wallet.SaultHandlerTest.class, "checkSaultProtocol");
                runTest(wallet.SaultHandlerTest.class, "checkWrongLength");


                System.out.println("\n--------------------------------------------");
                System.out.println("Start Ed25519 public key request testing");
                System.out.println("--------------------------------------------\n");
                runTest(wallet.PublicKeyTest.class, "testGetPubicKeyForDefaultPath");
                runTest(wallet.PublicKeyTest.class, "testGetPubicKey");
                runTest(wallet.PublicKeyTest.class, "testWrongLengthForGetPublicKeyWithDefaultHDPath");
                runTest(wallet.PublicKeyTest.class, "testWrongLengthForGetPublicKey");
                runTest(wallet.PublicKeyTest.class, "testGetPublicKeyAfterResetWalletAndGenerateSeed");
                runTest(wallet.PublicKeyTest.class, "testGetPublicKeyWithDefaultHDPathAfterResetWalletAndGenerateSeed");
                runTest(wallet.PublicKeyTest.class, "testPinExpiredForGetPublicKeyWithDefaultHDPath");
                runTest(wallet.PublicKeyTest.class, "testResetWallet");
                runTest(wallet.PublicKeyTest.class, "testPinExpiredForGetPublicKey");
                runTest(wallet.PublicKeyTest.class, "testResetWallet");

                System.out.println("\n--------------------------------------------");
                System.out.println("Start Ed25519 signature testing for default hd path");
                System.out.println("--------------------------------------------\n");
                runTest(wallet.Ed25519SignWithDefaultPathTest.class, "testSignWithDefaultPathVsSignShortForLen32");
                runTest(wallet.Ed25519SignWithDefaultPathTest.class, "testNotBlockingAndSuccessfullSigningAfterMacFailing");
                runTest(wallet.Ed25519SignWithDefaultPathTest.class, "testSignWithDefaultPathForLen32");
                runTest(wallet.Ed25519SignWithDefaultPathTest.class, "testSignWithDefaultPathForMaxLen");
                runTest(wallet.Ed25519SignWithDefaultPathTest.class, "testSignWithDefaultPathForMinLen");
                runTest(wallet.Ed25519SignWithDefaultPathTest.class, "testWrongLengthIncorrectLe");
                runTest(wallet.Ed25519SignWithDefaultPathTest.class, "testWrongLengthRandomData");
                runTest(wallet.Ed25519SignWithDefaultPathTest.class, "testWrongLengthForCorrectlyFormedDataForSigning");
                runTest(wallet.Ed25519SignWithDefaultPathTest.class, "testWrongLengthForMalformedDataForSigning");
                runTest(wallet.Ed25519SignWithDefaultPathTest.class, "testWrongLengthNoDataForSigning");
                runTest(wallet.Ed25519SignWithDefaultPathTest.class, "testSignWithDefaultPathWithoutPinVerification");
                runTest(wallet.Ed25519SignWithDefaultPathTest.class, "testSignWithDefaultPathWithIncorrectPin");
                runTest(wallet.Ed25519SignWithDefaultPathTest.class, "testIncorrectSault");
                runTest(wallet.Ed25519SignWithDefaultPathTest.class, "testOneIncorrectHmac");

                System.out.println("\n--------------------------------------------");
                System.out.println("Start Ed25519 signature testing");
                System.out.println("--------------------------------------------\n");
                runTest(wallet.Ed25519SignTest.class, "testSignForLen32ForRandomHdIndexes");
                runTest(wallet.Ed25519SignTest.class, "testSignForLen32");
                runTest(wallet.Ed25519SignTest.class, "testNotBlockingAndSuccessfullSigningAfterMacFailing");
                runTest(wallet.Ed25519SignTest.class, "testSignForMaxLen");
                runTest(wallet.Ed25519SignTest.class, "testSignForMinLen");
                runTest(wallet.Ed25519SignTest.class, "testSignWithoutPinVerification");
                runTest(wallet.Ed25519SignTest.class, "testSignWithoutPinVerificationForRandomHdIndexes");
                runTest(wallet.Ed25519SignTest.class, "testSignShortWithIncorrectPin");
                runTest(wallet.Ed25519SignTest.class, "testIncorrectSault");
                runTest(wallet.Ed25519SignTest.class, "testOneIncorrectHmac");
                runTest(wallet.Ed25519SignTest.class, "testKeyIndexEncoding");
                runTest(wallet.Ed25519SignTest.class, "testWrongLengthIncorrectLe");
                runTest(wallet.Ed25519SignTest.class, "testWrongLengthRandomData");
                runTest(wallet.Ed25519SignTest.class, "testWrongLengthNoDataAndNoHdIndexForSigning");
                runTest(wallet.Ed25519SignTest.class, "testWrongLengthNoDataAndCorrectHdIndexForSigning");
                runTest(wallet.Ed25519SignTest.class, "testWrongLengthCorrectDataAndNoHdIndexForSigning");
                runTest(wallet.Ed25519SignTest.class, "testWrongLengthForCorrectlyFormedDataForSigning");
                runTest(wallet.Ed25519SignTest.class, "testWrongLengthForMalformedDataForSigning");
                runTest(wallet.Ed25519SignTest.class, "testWrongLengthForMalformedHdIndex");
                runTest(wallet.Ed25519SignTest.class, "testSignWithoutPinVerification");

                System.out.println("\n--------------------------------------------");
                System.out.println("Pin handler testing");
                System.out.println("--------------------------------------------\n");
                runTest(wallet.PinHandlerTest.class, "testNotBlockingAndSuccessfullPinVerificationAfterMacFailing");
                runTest(wallet.PinHandlerTest.class, "testCorrectPinVerification");
                runTest(wallet.PinHandlerTest.class, "testOneIncorrectPinVerification");
                runTest(wallet.PinHandlerTest.class, "testPinNotExpiring");
                runTest(wallet.PinHandlerTest.class, "testPinExpiring");
                runTest(wallet.PinHandlerTest.class, "testNumberOfPinCheckFailsClearingAfterSuccess");
                runTest(wallet.PinHandlerTest.class, "testIncorrectSault");
                runTest(wallet.PinHandlerTest.class, "testWrongLength");
                runTest(wallet.PinHandlerTest.class, "testOneIncorrectHmac");



            }
            System.out.println("\n--------------------------------------------");
            System.out.println("All tests are passed.");

        }
        catch (Exception e) {
            e.printStackTrace();
        }



//      //  request = Request.method(wallet.PublicKeyTest.class, "testGetPubicKeyForDefaultPath");
//     //   Result result = new JUnitCore().run(request);
//

//
//
//        request = Request.method(wallet.Ed25519SignTest.class, "testSignForLen32ForRandomHdIndexes");
//        Result result = new JUnitCore().run(request);
//        System.out.println(result.getFailures());
//        result.
//
//
//        System.out.println("\n--------------------------------------------");
//        System.out.println("Start sault testing");
//        System.out.println("--------------------------------------------\n");
//

    }

    private static void runTest(Class testClass, String testMethodName) throws Exception {
        boolean methodIsPresent = false;
        for(int i = 0;  i < testClass.getMethods().length; i++)
            if (testClass.getMethods()[i].getName().equals(testMethodName)){
                methodIsPresent = true;
                break;
            }
        if (!methodIsPresent) {
                throw new Exception("Method " + testMethodName + " does not exist in " + testClass.getName());
        }
        System.out.println("\n Test method " + testMethodName + ": \n");
        Request request = Request.method(testClass, testMethodName);
        Result result = new JUnitCore().run(request);
        if (result.getFailureCount() > 0) {
            throw new Exception("Test failed: " + result.getFailures());
        }
    }




}
