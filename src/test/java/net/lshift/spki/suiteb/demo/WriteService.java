package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.read;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static net.lshift.spki.suiteb.Signed.signed;
import static net.lshift.spki.suiteb.sexpstructs.EcdhItem.ecdhItem;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.Registry;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.convert.openable.OpenableUtils;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;

public class WriteService {
    public static void writeService(
        PrivateSigningKey signingKey,
        Openable extra,
        PublicEncryptionKey recipient,
        Openable target,
        Service service)
                    throws IOException, InvalidInputException {
        Registry.getConverter(Service.class);
        PrivateEncryptionKey ephemeral = PrivateEncryptionKey.generate();
        OpenableUtils.write(target,
            sequence(
                ephemeral.getPublicKey(),
                ecdhItem(ephemeral, recipient),
                ephemeral.getKeyAsSender(recipient).encrypt(sequence(
                    read(extra),
                    signed(signingKey, new Action(service))))));
    }
}
