package wallet.smartcard.readerWrappers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import wallet.smartcard.cardReader.readerImpl.RealCardReader;

public class CardReaderWrapper {

    final protected static Logger log = LoggerFactory.getLogger(CardReaderWrapper.class);

    protected RealCardReader reader;

    public RealCardReader getReader() {
        return reader;
    }
}
