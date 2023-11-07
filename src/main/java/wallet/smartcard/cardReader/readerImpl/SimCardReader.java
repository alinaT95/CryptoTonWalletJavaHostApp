package wallet.smartcard.cardReader.readerImpl;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.io.CAD;
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import wallet.smartcard.cardReader.CardReader;
import wallet.smartcard.pcscWrapper.CAPDU;
import wallet.smartcard.pcscWrapper.RAPDU;
import wallet.smartcard.pcscWrapper.helpers.Keys;


import javax.smartcardio.CardException;
import java.io.File;

import static wallet.common.ByteArrayHelper.bConcat;
import static wallet.common.ByteArrayHelper.bytes;


public class SimCardReader extends CardReader {

    private final Class appletClass;
    private Simulator simulator;

    public SimCardReader(Class appletClass) throws CardException {
        this.appletClass = appletClass;
        System.setProperty("com.licel.jcardsim.terminal.type", "2");
        CAD cad = new CAD(System.getProperties());
        simulator = (JavaxSmartCardInterface) cad.getCardInterface();
    }


    @Override
    public void selectAID(String aid) throws CardException {
        byte[] appletAIDBytes = bytes(aid);
        AID appletAID = new AID(appletAIDBytes, (short) 0, (byte) appletAIDBytes.length);
        if(!simulator.selectApplet(appletAID)) {
            throw new CardException("Could not select AID");
        }
    }

    @Override
    public void install(File capFile, byte[] installData, byte[] execLoadFileAid, byte[] execModuleAid, byte[] instanceAid,
                        Keys isdKeys, byte[] cardManagerAid, byte[] hostChallenge) throws Exception {

        AID appletAID = new AID(instanceAid, (short) 0, (byte) instanceAid.length);

        byte[] appletData = bConcat(
              bytes(instanceAid.length), instanceAid // applet aid
            , bytes(0) // control info length
            , bytes(installData.length), installData // install data
        );

        simulator.installApplet(appletAID, appletClass, appletData, (short) 0, (byte) appletData.length);

    }

    @Override
    public RAPDU sendAPDU(CAPDU commandAPDU) throws CardException {
        byte[] resultBytes = simulator.transmitCommand(commandAPDU.getBytes());
        return new RAPDU(resultBytes);
    }

    @Override
    public RAPDU sendAPDU(String commandAPDU, String comment) throws CardException {
        return sendAPDU(new CAPDU(bytes(commandAPDU)));
    }

    @Override
     public RAPDU sendAPDU(CAPDU commandAPDU, String comment) throws CardException {
        return sendAPDU(commandAPDU);
    }
}
