package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.write;
import static net.lshift.spki.suiteb.Limit.limit;
import static net.lshift.spki.suiteb.SequenceUtils.sequenceOrItem;
import static net.lshift.spki.suiteb.Signed.signed;

import java.io.IOException;
import java.util.Date;

import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.suiteb.Condition;
import net.lshift.spki.suiteb.DigestSha384;
import net.lshift.spki.suiteb.InvalidOnOrAfter;
import net.lshift.spki.suiteb.PrivateSigningKey;
import net.lshift.spki.suiteb.PublicSigningKey;
import net.lshift.spki.suiteb.SequenceItem;

public class Master
{
    private final PrivateSigningKey key;
    private final PublicSigningKey publicKey;
    
    public Master()
    {
        key = PrivateSigningKey.generate();
        publicKey = key.getPublicKey();
    }
    
    public DigestSha384 getMasterPublicKeyId()
    {
        return publicKey.getKeyId();
    }

    public ByteOpenable delegateTrustTo(PublicSigningKey signingKey) throws IOException
    {
        return writeSequence(
            publicKey,
            signed(key, limit(signingKey,
                expiresInOneHour())));
    }

    private static ByteOpenable writeSequence(final SequenceItem... items) throws IOException {
        final ByteOpenable res = new ByteOpenable();
        write(res, sequenceOrItem(items));
        return res;
    }

    private static Condition expiresInOneHour() {
        return new InvalidOnOrAfter(
            new Date(System.currentTimeMillis() + 1000*3600));
    }
}
