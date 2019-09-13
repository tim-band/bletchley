package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static net.lshift.spki.suiteb.demo.Utilities.emptyByteOpenable;
import static net.lshift.spki.suiteb.demo.Utilities.read;

import java.io.IOException;

import net.lshift.bletchley.suiteb.demo.DemoProto.Service;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.suiteb.EncryptionCache;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.SequenceItem;

public class ServerWithEncryption extends Server {
    private final EncryptionCache ephemeral
        = new EncryptionCache(PrivateEncryptionKey.generate());
    private Openable recipientKey = emptyByteOpenable();

    public void setRecipientKey(Openable recipientKey) {
        this.recipientKey = recipientKey;
    }

    @Override
    protected SequenceItem serviceMessage(Service service) throws IOException,
            InvalidInputException {
        return encrypt(signedMessage(service));
    }

    protected SequenceItem encrypt(SequenceItem sequence) throws IOException,
            InvalidInputException {
        PublicEncryptionKey recipient
            = (PublicEncryptionKey) read(recipientKey);
        return sequence(ephemeral.getPublicKey(),
                ephemeral.encrypt(recipient, sequence));
    }
}
