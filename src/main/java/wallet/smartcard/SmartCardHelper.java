package wallet.smartcard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

public class SmartCardHelper {
    final private static Logger log = LoggerFactory.getLogger(SmartCardHelper.class);

    public static CardChannel tryOpenChannel() {
        try {
            CardChannel channel = null;
            for (CardTerminal terminal : TerminalFactory.getDefault().terminals().list()) {
                if(terminal.isCardPresent())
                    channel = terminal.connect("*").getBasicChannel();

            }
            if(channel == null) throw new RuntimeException("No card");
            return channel;
        } catch (CardException e) {
            throw new RuntimeException("Error while connecting to terminal", e);
        }
    }
}
