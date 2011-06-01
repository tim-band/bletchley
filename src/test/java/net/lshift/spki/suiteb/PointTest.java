package net.lshift.spki.suiteb;

import static net.lshift.spki.sexpform.Create.atom;
import static net.lshift.spki.sexpform.Create.list;

import java.io.IOException;

import net.lshift.spki.ParseException;
import net.lshift.spki.convert.ByteOpenable;
import net.lshift.spki.convert.OpenableUtils;
import net.lshift.spki.sexpform.Sexp;
import net.lshift.spki.suiteb.sexpstructs.Point;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

public class PointTest {
    @Test(expected=ParseException.class)
    public void badPointRejected() throws IOException, ParseException {
        ByteOpenable example = new ByteOpenable();
        Sexp sexp = list("point",
            list("x", atom("asdf")),
            list("y", atom("qwert")));
        OpenableUtils.write(Sexp.class, sexp, example);
        OpenableUtils.read(ECPoint.class, example);
    }

    static {
        Point.ensureRegistered();
    }
}
