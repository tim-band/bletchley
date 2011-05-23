package net.lshift.spki.convert;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Interface for objects that can be opened for reading or writing. Handy
 * for defining the CLI in a unit-testable way.
 */
public interface Openable {
    InputStream read() throws IOException;

    OutputStream write() throws IOException;
}
