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
            "8e6ec45ebea13cc7190a8caf243f0d88ea8d6bded69f4df3" + 
            "0657f3c8cd5f9d74f25021380bc77f2030ad2c8259fd8bab"))));
    }
}

