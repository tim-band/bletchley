package net.lshift.spki.convert;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface Openable
{
    InputStream read() throws IOException;

    OutputStream write() throws IOException;
}
