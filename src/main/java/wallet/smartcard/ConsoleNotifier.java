package wallet.smartcard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class ConsoleNotifier implements INotifier{

    final private static Logger log = LoggerFactory.getLogger(ConsoleNotifier.class);


    @Override
    public void notify(String message) {
        System.out.println(message);
    }
}
