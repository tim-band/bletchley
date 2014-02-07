package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.write;
import static net.lshift.spki.suiteb.Limit.limit;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static net.lshift.spki.suiteb.Signed.signed;

import java.io.IOException;
import java.util.Date;

import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.suiteb.Condition;
import net.lshift.spki.suiteb.InvalidOnOrAfter;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicSigningKey;

public class Master {
    private final PrivateSigningKey privateKey;

    public Master() {
        privateKey = PrivateSigningKey.generate();
    }

    public void writeMasterTrust(Openable target) throws IOException {
        write(target, privateKey.getPublicKey().getKeyId());
    }

    public void delegateTrustTo(Openable target, PublicSigningKey signingKey)
            throws IOException {
        write(target, sequence(privateKey.getPublicKey(),
                signed(privateKey, limit(signingKey, expiresInOneHour()))));
    }

    private static Condition expiresInOneHour() {
        return new InvalidOnOrAfter(new Date(
                System.currentTimeMillis() + 1000 * 3600));
    }
}
