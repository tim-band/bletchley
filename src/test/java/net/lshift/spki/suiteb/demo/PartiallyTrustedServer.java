package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.read;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static net.lshift.spki.suiteb.Signed.signed;
import static net.lshift.spki.suiteb.demo.Utilities.R;
import static net.lshift.spki.suiteb.demo.Utilities.emptyByteOpenable;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.SequenceItem;

public class PartiallyTrustedServer extends ServerWithEncryption {
    private final Openable certificate = emptyByteOpenable();

    public Openable getCertificate() {
        return certificate;
    }

    @Override
    protected SequenceItem serviceMessage(Service service) throws IOException, InvalidInputException {
        return encrypt(sequence(read(R, certificate),
                signed(signingKey, new Action(service))));
    }
}
