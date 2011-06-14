package net.lshift.spki.convert;

import static net.lshift.spki.sexpform.Create.atom;
import static net.lshift.spki.sexpform.Create.list;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.sexpform.Sexp;
import net.lshift.spki.suiteb.sexpstructs.Point;

import org.junit.Test;

public class NameBeanTest {
    @Test(expected=ConvertException.class)
    public void repeatedFieldsRejected() throws IOException, InvalidInputException {
        final ByteOpenable example = new ByteOpenable();
        OpenableUtils.write(Sexp.class,
            list("point",
                list("x", atom("foo")),
                list("x", atom("bar"))), example);
        OpenableUtils.read(Point.class, example);
    }

}
