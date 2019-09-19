package net.lshift.spki.suiteb;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import net.lshift.spki.convert.UsesSimpleMessage;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class DigestTest extends UsesSimpleMessage
{
    @Test
    public void digestValueMatches() {
        final DigestSha384 digest
            = DigestSha384.digest(makeMessage());
        assertThat(digest, is(new DigestSha384(Hex.decode(
            "af03dee21dedc87aaa673badaadc7fa83a88c700ad6ac4cf" +
            "d6bcb8a600603874bef28a1ac1e048c071ac88c95bc30215"))));
    }
}
