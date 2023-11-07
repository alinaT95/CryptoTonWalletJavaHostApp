package wallet.testHelper;

import wallet.smartcard.CardState;
import wallet.smartcard.ConsoleNotifier;
import wallet.tonWalletApi.WalletHostAPI;

public class CardConnector {
    protected WalletHostAPI walletHostAPI;

    public CardConnector(WalletHostAPI walletHostAPI) {
        this.walletHostAPI = walletHostAPI;
    }

    public void connect(){
        ConsoleNotifier consoleNotifier = new ConsoleNotifier();

        WalletHostAPI.setAndStartCardsStateWatcher(consoleNotifier);

        try {
            boolean isConnected = false;

            while ( !isConnected) {
                WalletHostAPI.refreshCardState();

                System.out.println("Waiting for the card...");
                if (WalletHostAPI.getCardReaderWrapperCurState()) { // Card is inserted

                    CardState state = WalletHostAPI.getWalletCardState();

                    switch (state) {
                        case NOT_INSERTED : {
                            System.out.println("Wallet Applet is NOT_INSERTED");
                            break;
                        }
                        case INSTALLED : {
                            System.out.println("Wallet Applet is INSTALLED");
                           // walletHostAPI.personlizeAppletFromCsv();
                             walletHostAPI.personlizeAppletFromHardcodedData();//
                           // walletHostAPI.personalizeApplet();
                            //walletHostAPI.getHashOfEncryptedPassword();
                            break;
                        }
                        case INVALID : {
                            System.out.println("Wallet Applet is invalid");
                            break;
                        }
                        case EMPTY : { // Card is empty
                            System.out.println("Wallet Applet is not installed");
                            break;
                        }
                        case BLOCKED: {
                            System.out.println("Wallet Applet is blocked");
                            isConnected = true;
                            break;
                        }
                        case WAIT_AUTHENTICATION: {
                            System.out.println("Wallet Applet is waiting for password authentication");
                            isConnected = true;
                            break;
                        }
                        default: { // Card is not empty
                            System.out.println("Wallet Applet is ongoing");
                            isConnected = true;
                            break;
                        }

                    }

                    try {
                        Thread.sleep(3000);
                    } catch (InterruptedException e1) {
                    }
                }
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}
