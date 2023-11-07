package wallet.smartcard.pcscWrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import wallet.smartcard.pcscWrapper.helpers.ErrorCodes;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import static wallet.smartcard.WalletAppletConstants.*;


import static wallet.common.ByteArrayHelper.bytes;
import static wallet.common.ByteArrayHelper.hex;

public class ApduRunner {
    final private static Logger log = LoggerFactory.getLogger(ApduRunner.class);

    private final CardChannel channel;

    private String name = "Unknown Reader";

    public ApduRunner(CardChannel basicChannel) throws CardException {
        this.channel = basicChannel;
    }

    public ApduRunner(CardChannel basicChannel, String name) throws CardException {
        this.channel = basicChannel;
        this.name = name;
    }

    public CardChannel getChannel() {
        return channel;
    }

    public RAPDU sendAPDU(CAPDU capdu) throws CardException {
        return sendAPDU(capdu, null);
    }

    public RAPDU sendAPDU(String apdu, String comment) throws CardException {
        return sendAPDU(new CAPDU(bytes(apdu)), comment);
    }

    public RAPDU sendAPDU(CAPDU commandAPDU, String comment) throws CardException {
        System.out.println("===============================================================");
        System.out.println(name + ":");
        System.out.println("===============================================================");
        String apduFormated = hex(commandAPDU.getCla()) + " "
                + hex(commandAPDU.getIns()) + " "
                + hex(commandAPDU.getP1()) + " "
                + hex(commandAPDU.getP2()) + " "
                + hex(commandAPDU.getLc()) + " "
                + hex(commandAPDU.getData()) + " "
                + hex((byte)commandAPDU.getLe()) + " "
                + (comment != null
                    ? " (" + comment + ")"
                    : commandAPDU.getDescr() != null
                        ? " (" + commandAPDU.getDescr() + ")"
                        : "");

        System.out.println("Send apdu  " + apduFormated);
        if (getCommandName(commandAPDU.getIns()) != null)
            System.out.println("(" + getCommandName(commandAPDU.getIns()) +")");
        ResponseAPDU transmit = channel.transmit(new CommandAPDU(commandAPDU.getBytes()));
        RAPDU rapdu = new RAPDU(transmit.getBytes());


        StringBuilder msg = new StringBuilder();

        String swFormatted = hex(new byte [] {(byte) transmit.getSW1()} )
                + hex(new byte[]{(byte) transmit.getSW2()});

        if(ErrorCodes.getMsg(transmit) != null)
            swFormatted += ", "+ ErrorCodes.getMsg(transmit);

        msg.append("SW1-SW2: " + swFormatted);
       // msg.append("SW message: " + ErrorCodes.getMsg(ByteArrayHelper.hex(swFormatted)));

        String bytes = hex(transmit.getBytes());
        bytes = bytes.substring(0, bytes.length() - 4);

        if(bytes.length() > 0)
            msg.append(", bytes: " + bytes);

        System.out.println(msg.toString());

        commandAPDU.printMore(rapdu);
        System.out.println("===============================================================");

        // Check result for success result
        boolean success = false;
        for (byte[] successA : commandAPDU.getSuccessResults()) {
            if ((byte)transmit.getSW1() == successA[0] && (byte)transmit.getSW2() == successA[1]) {
                success = true; break;
            }
        }
        if (!success) {
            throw new CardException("Operation failed (" + swFormatted + "): " + apduFormated);
        }

        return rapdu;
    }

}
