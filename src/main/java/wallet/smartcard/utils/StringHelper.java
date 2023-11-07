package wallet.smartcard.utils;

public class StringHelper {
    public static String extendStringByZeros(String s) {
        StringBuilder stringBuilder = new StringBuilder();
        for(int i = 0; i < s.length(); i++)
            stringBuilder.append("0").append(s.charAt(i));
        return stringBuilder.toString();
    }
}
