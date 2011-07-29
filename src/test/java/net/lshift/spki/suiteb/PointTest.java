package net.lshift.spki.suiteb;

import static net.lshift.spki.sexpform.Create.atom;
import static net.lshift.spki.sexpform.Create.list;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ByteOpenable;
import net.lshift.spki.convert.ConvertException;
import net.lshift.spki.convert.OpenableUtils;
import net.lshift.spki.convert.Registry;
import net.lshift.spki.convert.ResetsRegistry;
import net.lshift.spki.sexpform.Sexp;
import net.lshift.spki.suiteb.sexpstructs.ECPointConverter;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

public class PointTest extends ResetsRegistry {
    @Test(expected=ConvertException.class)
    public void badPointRejected() throws IOException, InvalidInputException {
        final ByteOpenable example = new ByteOpenable();
        final Sexp sexp = list("point",
            list("x", atom("asdf")),
            list("y", atom("qwert")));
        OpenableUtils.write(Sexp.class, sexp, example);
        OpenableUtils.read(ECPoint.class, example);
    }

    @Before
    public void registerPoint() {
        Registry.register(new ECPointConverter());
    }
}
