package net.lshift.spki.suiteb;

import static net.lshift.spki.sexpform.Create.atom;
import static net.lshift.spki.sexpform.Create.list;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.ByteOpenable;
import net.lshift.spki.convert.ConvertException;
import net.lshift.spki.convert.OpenableUtils;
import net.lshift.spki.sexpform.Sexp;
import net.lshift.spki.suiteb.sexpstructs.Point;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

public class PointTest {
    @Test(expected=ConvertException.class)
    public void badPointRejected() throws IOException, InvalidInputException {
        final ByteOpenable example = new ByteOpenable();
        final Sexp sexp = list("point",
            list("x", atom("asdf")),
            list("y", atom("qwert")));
        OpenableUtils.write(Sexp.class, sexp, example);
        OpenableUtils.read(ECPoint.class, example);
    }

    static {
        Point.ensureRegistered();
    }
}
