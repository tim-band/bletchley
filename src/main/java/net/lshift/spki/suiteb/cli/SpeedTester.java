package net.lshift.spki.suiteb.cli;

import java.util.ArrayList;
import java.util.List;

import net.lshift.spki.ParseException;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SequenceItem;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

public class SpeedTester {
    private static final String MESSAGE_TYPE = "speed-test-message";
    private final PrivateSigningKey privateKey;
    private final byte[] publicKeyBytes;
    private final byte[] messageBytes;

    public SpeedTester() {
        super();
        this.privateKey = PrivateSigningKey.generate();
        this.publicKeyBytes = ConvertUtils.toBytes(
            PublicEncryptionKey.class,
            PrivateEncryptionKey.generate().getPublicKey());
        this.messageBytes = new byte[100];
    }

    public void speedTest() throws ParseException {
        doRun();
        long start = System.currentTimeMillis();
        for (int i = 0; ; i++) {
            long end = System.currentTimeMillis();
            if (end - start > 5000) {
                System.out.println("Time (ms): " + (end-start)*1.0/i);
                break;
            }
            doRun();
        }
    }

    private void doRun() throws ParseException {
        List<SequenceItem> sequenceItems = new ArrayList<SequenceItem>();
        AesKey aesKey = AesKey.generateAESKey();
        PublicEncryptionKey pKey
            = ConvertUtils.fromBytes(PublicEncryptionKey.class, publicKeyBytes);
        AesKey rKey = pKey.setupEncrypt(sequenceItems);
        sequenceItems.add(rKey.encrypt(aesKey));

        List<SequenceItem> encryptedSequenceItems
            = new ArrayList<SequenceItem>();
        SimpleMessage message = new SimpleMessage(
            MESSAGE_TYPE, messageBytes);
        encryptedSequenceItems.add(privateKey.sign(message));
        encryptedSequenceItems.add(message);

        sequenceItems.add(aesKey.encrypt(new Sequence(encryptedSequenceItems)));

        ConvertUtils.toBytes(Sequence.class, new Sequence(sequenceItems));
    }

}
