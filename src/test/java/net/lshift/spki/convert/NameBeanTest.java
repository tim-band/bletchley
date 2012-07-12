package net.lshift.spki.convert;

import static net.lshift.spki.sexpform.Create.atom;
import static net.lshift.spki.sexpform.Create.list;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.openable.ByteOpenable;
import net.lshift.spki.convert.openable.OpenableUtils;
import net.lshift.spki.suiteb.sexpstructs.ECPointConverter.Point;

import org.junit.Test;

public class NameBeanTest extends UsesReadInfo {
    @Test(expected=ConvertException.class)
    public void repeatedFieldsRejected() throws IOException, InvalidInputException {
        final ByteOpenable example = new ByteOpenable();
        OpenableUtils.write(example, list("point",
            list("x", atom("foo")),
            list("x", atom("bar"))));
        OpenableUtils.read(getReadInfo(), Point.class, example);
    }
}
