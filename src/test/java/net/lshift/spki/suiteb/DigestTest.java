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
            "ba4c9bcfa96ada720fccfd68f66735dfc55762a5cda126b4" + 
            "6d1dffcc51a09ddfb64b8da61e8f5d41cada1bc9c2eb64c3"))));
    }
}

