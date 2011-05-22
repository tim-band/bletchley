package net.lshift.spki.convert;

import java.io.ByteArrayInputStream;

import net.lshift.spki.CanonicalSpkiInputStream;
import net.lshift.spki.Marshal;
import net.lshift.spki.Sexp;

public class TestUtils
{
    public static ConvertInputStream toConvert(Sexp sexp)
    {
        return new ConvertInputStream(
            new CanonicalSpkiInputStream(
                new ByteArrayInputStream(
                    Marshal.marshal(sexp))));
    }
}
