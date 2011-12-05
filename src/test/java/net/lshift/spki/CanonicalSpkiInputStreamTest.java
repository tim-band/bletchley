package net.lshift.spki;

import java.io.InputStream;

public class CanonicalSpkiInputStreamTest extends SpkiInputStreamTest
{
    @Override
    protected void setInput(InputStream inputStream) {
        sis = new CanonicalSpkiInputStream(inputStream);
    }
}
