package wallet.smartcard.cardReader;


import wallet.smartcard.pcscWrapper.CAPDU;
import wallet.smartcard.pcscWrapper.RAPDU;
import wallet.smartcard.pcscWrapper.helpers.Keys;

import javax.smartcardio.CardException;
import java.io.File;

public abstract class CardReader {
    public abstract void selectAID(String aid) throws CardException;

    public abstract void install(File capFile, byte[] installData, byte[] execLoadFileAid, byte[] execModuleAid, byte[] instanceAid, Keys isdKeys, byte[] cardManagerAid, byte[] hostChallenge) throws Exception;

    public abstract RAPDU sendAPDU(CAPDU commandApdu) throws CardException;

    public abstract RAPDU sendAPDU(String commandApdu, String comment) throws CardException;

    public abstract RAPDU sendAPDU(CAPDU commandApdu, String comment) throws CardException;
}
