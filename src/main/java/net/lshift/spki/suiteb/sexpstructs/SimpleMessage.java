package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertable;
import net.lshift.spki.convert.SExpName;

/**
 * Format for a simple kind of message - just identifier and data - that
 * can be encrypted and/or signed.
 */
public class SimpleMessage extends PositionBeanConvertable
{
    public final String type;
    public final byte[] content;

    @SExpName("simple-message")
    public SimpleMessage(
        @P("type") String type,
        @P("content") byte[] content)
    {
        super();
        this.type = type;
        this.content = content;
    }
}
