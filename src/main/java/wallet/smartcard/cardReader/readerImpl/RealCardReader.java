package wallet.smartcard.cardReader.readerImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import wallet.smartcard.SecurityDomainHelper;
import wallet.smartcard.cardReader.CardReader;
import wallet.smartcard.pcscWrapper.ApduRunner;
import wallet.smartcard.pcscWrapper.CAPDU;
import wallet.smartcard.pcscWrapper.RAPDU;
import wallet.smartcard.pcscWrapper.gp.InitializeUpdateCAPDU;
import wallet.smartcard.pcscWrapper.gp.SelectAidCAPDU;
import wallet.smartcard.pcscWrapper.helpers.Keys;
import wallet.smartcard.pcscWrapper.helpers.SessionKeys;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import java.io.File;


import static wallet.common.ByteArrayHelper.bytes;

public class RealCardReader extends CardReader {

    final private static Logger log = LoggerFactory.getLogger(RealCardReader.class);

    private ApduRunner apduRunner;


    public RealCardReader(CardChannel cardChannel) throws CardException {
        apduRunner = new ApduRunner(cardChannel);
    }

    public RealCardReader(CardChannel cardChannel, String name) throws CardException {
        apduRunner = new ApduRunner(cardChannel, name);
    }

    public ApduRunner getApduRunner() {
        return apduRunner;
    }

    @Override
    public void selectAID(String aid) throws CardException {

        byte[] data = bytes(String.format("00A40400%02X%s", aid.length() / 2, aid));


        this.sendAPDU(new CAPDU(data));
    }

    @Override
    public void install(File capFile, byte[] installData, byte[] execLoadFileAid, byte[] execModuleAid, byte[] instanceAid, Keys isdKeys, byte[]
            cardManagerAid, byte[] hostChallenge) throws Exception {
        SecurityDomainHelper.installApp(apduRunner, true, true, cardManagerAid,
                hostChallenge, isdKeys, execLoadFileAid, execModuleAid, instanceAid, capFile, installData);
    }


    /// new ///
    public void install(File capFile, byte[] installData, byte[] execLoadFileAid, byte[] execModuleAid, byte[] instanceAid,
                        SessionKeys sessionKeys, byte[] cardManagerAid, byte[] hostChallenge, byte[] initUpdResp) throws Exception {
        SecurityDomainHelper.installApp(apduRunner, true, true, cardManagerAid, hostChallenge,
                sessionKeys, execLoadFileAid, execModuleAid, instanceAid, capFile, installData, initUpdResp);
    }

    public void install(File capFileLib, File capFileApp, byte[] installData, byte[] execLoadFileLibAid, byte[] execLoadFileAppAid,
                        byte[] execModuleAid, byte[] instanceAid, SessionKeys sessionKeys, byte[] cardManagerAid, byte[] hostChallenge, byte[] initUpdResp) throws Exception {
        SecurityDomainHelper.installApp(apduRunner, true, true, cardManagerAid, hostChallenge,
                sessionKeys, execLoadFileLibAid, execLoadFileAppAid, execModuleAid, instanceAid,
                capFileLib, capFileApp, installData, initUpdResp);
    }


    /// new ///
    public byte[] initializeUpdate(byte[] sdAid, byte[] hostChallenge) throws Exception {

        /*
         SELECT
          */
        apduRunner.sendAPDU(new SelectAidCAPDU(sdAid), "Select Card Manager");

        /*
         INITIALIZE UPDATE
          */

        RAPDU initUpdResp = apduRunner.sendAPDU(new InitializeUpdateCAPDU(hostChallenge));

        return initUpdResp.getData();
    }

    /// new ///
    public void delete(boolean deletePackage, byte[] execLoadFileAid, byte[] instanceAid, Keys sdKeys, byte[] cardManagerAid, byte[] hostChallenge) throws Exception {
        SecurityDomainHelper.deleteApp(apduRunner, deletePackage,cardManagerAid, hostChallenge, sdKeys, execLoadFileAid, instanceAid);
    }

    /// new ///
    public void delete(boolean deletePackage, byte[] execLoadFileAid, byte[] instanceAid, SessionKeys sessionKeys, byte[] cardManagerAid, byte[] hostChallenge, byte[] initUpdResp) throws Exception {
        SecurityDomainHelper.deleteApp(apduRunner, deletePackage, cardManagerAid, hostChallenge, sessionKeys, execLoadFileAid, instanceAid, initUpdResp);
    }



    @Override
    public RAPDU sendAPDU(CAPDU commandAPDU) throws CardException {
        return apduRunner.sendAPDU(commandAPDU);
    }

    @Override
    public RAPDU sendAPDU(String commandAPDU, String comment) throws CardException {
        return apduRunner.sendAPDU(commandAPDU, comment);
    }

    @Override
    public RAPDU sendAPDU(CAPDU commandAPDU, String comment) throws CardException {
        return apduRunner.sendAPDU(commandAPDU, comment);
    }

}
