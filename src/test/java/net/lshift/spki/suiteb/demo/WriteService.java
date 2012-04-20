package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.read;
import static net.lshift.spki.convert.openable.OpenableUtils.write;
import static net.lshift.spki.suiteb.Signed.signed;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Registry;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.EncryptionCache;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;

public class WriteService {
    private static EncryptionCache ephemeral =
                    new EncryptionCache(PrivateEncryptionKey.generate());

    public static void writeService(
        final Openable target,
        final Openable extra,
        final PrivateSigningKey signingKey,
        final PublicEncryptionKey recipient,
        final Service service)
                    throws IOException, InvalidInputException {
        Registry.getConverter(Service.class);
        write(target,
            ephemeral.encrypt(recipient,
                read(extra),
                signed(signingKey, new Action(service))));
    }
}
