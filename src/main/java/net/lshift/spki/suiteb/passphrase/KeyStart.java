package net.lshift.spki.suiteb.passphrase;

import com.google.protobuf.ByteString;

import net.lshift.bletchley.suiteb.proto.PassphraseProto;
import net.lshift.bletchley.suiteb.proto.PassphraseProto.KeyStart.Builder;
import net.lshift.spki.convert.ProtobufConvertible;

public class KeyStart implements ProtobufConvertible<PassphraseProto.KeyStart.Builder> {
    // This class is only used to create a digest, so no access to the fields
    // is required, other than to convert to a protobuf
    private final String passphraseId;
    private final byte [] salt;
    private final Integer iterations;
    private final String passphrase;

    public KeyStart(final String passphraseId, final byte[] salt, final int iterations,
                    final String passphrase) {
        this.passphraseId = passphraseId;
        this.salt = salt;
        this.iterations = iterations;
        this.passphrase = passphrase;
    }

    @Override
    public Builder toProtobuf() {
        return PassphraseProto.KeyStart.newBuilder()
                .setPassphraseId(passphraseId)
                .setSalt(ByteString.copyFrom(salt))
                .setIterations(iterations)
                .setPassphrase(passphrase);
    }
}
