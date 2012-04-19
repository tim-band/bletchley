package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static net.lshift.spki.suiteb.Signed.signed;

import java.io.IOException;

import net.lshift.spki.convert.Registry;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.convert.openable.OpenableUtils;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.SequenceItem;
import net.lshift.spki.suiteb.sexpstructs.EcdhItem;

public class WriteService {
    public static void writeService(
        PrivateSigningKey signingKey,
        PublicEncryptionKey recipient,
        Openable target,
        Service service)
                    throws IOException {
        Registry.getConverter(Service.class);
        PrivateEncryptionKey ephemeral = PrivateEncryptionKey.generate();
        final Action action = new Action(service);
        OpenableUtils.write(SequenceItem.class,
            sequence(
                ephemeral.getPublicKey(),
                EcdhItem.ecdhItem(ephemeral, recipient),
                ephemeral.getKeyAsSender(recipient).encrypt(sequence(
                    signingKey.sign(action),
                    signed(action)))),
        target);
    }
}
