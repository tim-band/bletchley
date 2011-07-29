package net.lshift.spki.suiteb.cli;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ConvertUtils;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.EncryptionSetup;
import net.lshift.spki.suiteb.PrivateEncryptionKey;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicEncryptionKey;
import net.lshift.spki.suiteb.SequenceUtils;
import net.lshift.spki.suiteb.sexpstructs.Sequence;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

/**
 * Quick and dirty speed test visible from the CLI.
 */
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

    public void speedTest() throws InvalidInputException {
        doRun();
        final long start = System.currentTimeMillis();
        for (int i = 0; ; i++) {
            final long end = System.currentTimeMillis();
            if (end - start > 5000) {
                System.out.println("Time (ms): " + (end-start)*1.0/i);
                break;
            }
            doRun();
        }
    }

    private void doRun() throws InvalidInputException {
        final AesKey aesKey = AesKey.generateAESKey();
        final PublicEncryptionKey pKey
            = ConvertUtils.fromBytes(PublicEncryptionKey.class, publicKeyBytes);
        final EncryptionSetup rKey = pKey.setupEncrypt();

        final SimpleMessage message = new SimpleMessage(
            MESSAGE_TYPE, messageBytes);

        final Sequence sequence = SequenceUtils.sequence(
            rKey.encryptedKey,
            rKey.key.encrypt(aesKey),
            aesKey.encrypt(SequenceUtils.sequence(
                privateKey.sign(message),
                message
        )));
        ConvertUtils.toBytes(Sequence.class, sequence);
    }

}
