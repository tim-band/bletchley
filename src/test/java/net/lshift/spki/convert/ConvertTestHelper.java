package net.lshift.spki.convert;

import java.io.ByteArrayInputStream;

import net.lshift.spki.CanonicalSpkiInputStream;
import net.lshift.spki.Sexp;

public class ConvertTestHelper
{
    public static ConvertInputStream toConvert(Sexp sexp)
    {
        return new ConvertInputStream(
            new CanonicalSpkiInputStream(
                new ByteArrayInputStream(
                    ConvertUtils.toBytes(Sexp.class, sexp))));
    }
}
