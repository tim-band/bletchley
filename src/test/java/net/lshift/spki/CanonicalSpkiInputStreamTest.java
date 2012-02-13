package net.lshift.spki;

import java.io.InputStream;

public class CanonicalSpkiInputStreamTest extends SpkiInputStreamTest
{
    @Override
    protected void setInput(final InputStream inputStream) {
        sis = new CanonicalSpkiInputStream(inputStream);
    }
}
