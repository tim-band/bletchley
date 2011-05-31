package net.lshift.spki.convert;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.LongBuffer;
import java.util.UUID;

import net.lshift.spki.ParseException;


public class UUIDConverter
    implements Converter<UUID>
{


    @Override
    public void write(ConvertOutputStream out, UUID o)
        throws IOException
    {
        ByteBuffer bytes = ByteBuffer.wrap(new byte[16]);
        LongBuffer longs = bytes.asLongBuffer();
        longs.put(o.getMostSignificantBits());
        longs.put(o.getLeastSignificantBits());
        out.atom(bytes.array());
        
    }

    @Override
    public UUID read(ConvertInputStream in)
        throws ParseException,
            IOException
    {
        LongBuffer longs = ByteBuffer.wrap(in.atomBytes()).asLongBuffer();
        return new UUID(longs.get(), longs.get());
    }

}
