package wallet.smartcard.pcscWrapper.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Pair<T1,T2> {
    final private static Logger log = LoggerFactory.getLogger(Pair.class);

    public final T1 first;
    public final T2 second;

    public Pair(T1 first, T2 second) {
        this.first = first;
        this.second = second;
    }

    public static <T1,T2> Pair<T1,T2> Pair(T1 first, T2 second)
    {
        return new Pair<>(first, second);
    }
}
