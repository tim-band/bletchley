package net.lshift.spki.suiteb;

import static net.lshift.spki.sexpform.Create.atom;
import static net.lshift.spki.sexpform.Create.list;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.UsesConverting;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.convert.openable.OpenableUtils;
import net.lshift.spki.sexpform.Sexp;
import net.lshift.spki.suiteb.sexpstructs.EcdhPublicKey;

import org.junit.Test;

public class PointTest extends UsesConverting {
    @Test(expected=CryptographyException.class)
    public void badPointRejected() throws IOException, InvalidInputException {
        final ByteOpenable example = new ByteOpenable();
        final Sexp sexp = list("suiteb-p384-ecdh-public-key",
            list("point",
                list("x", atom("asdf")),
                list("y", atom("qwert"))));
        OpenableUtils.write(example, sexp);
        OpenableUtils.read(C, EcdhPublicKey.class, example);
    }
}
