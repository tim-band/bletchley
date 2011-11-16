package net.lshift.spki.suiteb.passphrase;

import java.io.Console;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.suiteb.AesKey;

/**
 * Simple PassphraseDelegate to ask the user for a passphrase
 * on the console.
 */
public class ConsolePassphraseDelegate
    implements PassphraseDelegate {
    @Override
    public AesKey getPassphrase(PassphraseProtectedKey ppk) {
        Console console = System.console();
        if (console == null) {
            return null;
        }
        while (true) {
            final String passphrase = new String(console.readPassword(
                "Passphrase for \"%s\": ", ppk.getPassphraseId()));
            try {
                return ppk.getKey(passphrase);
            } catch (InvalidInputException e) {
                if (passphrase.isEmpty()) {
                    return null;
                }
                System.out.println("Wrong passphrase, trying again");
            }
        }
    }
}
