package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static net.lshift.spki.suiteb.Signed.signed;

import java.io.IOException;

import net.lshift.spki.convert.Registry;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.convert.openable.OpenableUtils;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.SequenceItem;

public class WriteService {
    public static void writeService(
        PrivateSigningKey signingKey,
        Openable target,
        Service service)
                    throws IOException {
        Registry.getConverter(Service.class);
        final Action action = new Action(service);
        OpenableUtils.write(SequenceItem.class, sequence(
                signingKey.sign(action),
                signed(action)), target);
    }
}
