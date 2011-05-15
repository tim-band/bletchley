package net.lshift.spki.convert;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.io.IOUtils;

public class OpenableUtils
{

    public static byte[] readBytes(Openable message)
        throws IOException
    {
        final InputStream is = message.read();
        try {
            return IOUtils.toByteArray(is);
        } finally {
            is.close();
        }
    }

    public static void writeBytes(Openable out, final byte[] messageBytes)
        throws IOException
    {
        OutputStream os = out.write();
        try {
            os.write(messageBytes);
        } finally {
            os.close();
        }
    }

}
