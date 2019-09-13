package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static net.lshift.spki.suiteb.Signed.signed;
import static net.lshift.spki.suiteb.demo.Utilities.emptyByteOpenable;
import static net.lshift.spki.suiteb.demo.Utilities.read;

import java.io.IOException;

import com.google.protobuf.Any;

import net.lshift.bletchley.suiteb.demo.DemoProto.Service;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.suiteb.Action;
import net.lshift.spki.suiteb.SequenceItem;

public class PartiallyTrustedServer extends ServerWithEncryption {
    private Openable certificate = emptyByteOpenable();

    public void setCertificate(Openable certificate) {
        this.certificate = certificate;
    }

    @Override
    protected SequenceItem serviceMessage(Service service) throws IOException, InvalidInputException {
        return encrypt(sequence(read(certificate),
                signed(signingKey, new Action(Any.pack(service)))));
    }
}
