package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.read;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static net.lshift.spki.suiteb.Signed.signed;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.suiteb.Action;

public class PartiallyTrustedServer extends ServerWithEncryption {
    private ByteOpenable certificate;

    public void setCertificate(ByteOpenable certificate) {
        this.certificate = certificate;
    }

    @Override
    public ByteOpenable generateMessage(Service service) throws IOException,
            InvalidInputException {
        return asOpenable(encrypt(sequence(read(R, certificate),
                signed(signingKey, new Action(service)))));
    }
}
