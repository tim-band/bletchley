package net.lshift.spki.convert;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import net.lshift.spki.sexpform.Sexp;

public class ConvertTestHelper
{
    public static InputStream toConvert(Sexp sexp)
    {
        return new ByteArrayInputStream(
            ConvertUtils.toBytes(Sexp.class, sexp));
    }
}
