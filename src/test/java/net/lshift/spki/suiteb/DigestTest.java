package net.lshift.spki.suiteb;

import static net.lshift.spki.Create.atom;
import static net.lshift.spki.Create.list;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import net.lshift.spki.Sexp;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class DigestTest
{
    @Test
    public void digestValueMatches() {
        DigestSha384 digest
            = DigestSha384.digest(Sexp.class, list(atom("foo")));
        assertThat(digest, is(new DigestSha384(Hex.decode(
            "7da6c98a1ec8e81aa6e5aab9f27094e4434c468f5fba4650" +
            "04297a26b2faf7f02f6f04d36b95406e366d62c0945e58a1"))));
    }
}
