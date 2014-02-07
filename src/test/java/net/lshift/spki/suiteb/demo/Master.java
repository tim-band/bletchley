package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.suiteb.Limit.limit;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;
import static net.lshift.spki.suiteb.Signed.signed;
import static net.lshift.spki.suiteb.demo.Utilities.asOpenable;

import java.io.IOException;
import java.util.Date;

import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.suiteb.Condition;
import net.lshift.spki.suiteb.InvalidOnOrAfter;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicSigningKey;

public class Master {
    private final PrivateSigningKey privateKey = PrivateSigningKey.generate();

    public Openable writeMasterTrust() throws IOException {
        return asOpenable(privateKey.getPublicKey().getKeyId());
    }

    public Openable delegateTrustTo(PublicSigningKey signingKey)
            throws IOException {
        return asOpenable(sequence(privateKey.getPublicKey(),
                signed(privateKey, limit(signingKey, expiresInOneHour()))));
    }

    private static Condition expiresInOneHour() {
        return new InvalidOnOrAfter(new Date(
                System.currentTimeMillis() + 1000 * 3600));
    }
}
