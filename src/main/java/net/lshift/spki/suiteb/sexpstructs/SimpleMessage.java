package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertable;
import net.lshift.spki.convert.SExpName;

public class SimpleMessage extends PositionBeanConvertable
{
    private final String type;
    private final byte[] content;

    @SExpName("simple-message")
    public SimpleMessage(
        @P("type") String type,
        @P("content") byte[] content)
    {
        super();
        this.type = type;
        this.content = content;
    }

    public String getType()
    {
        return type;
    }

    public byte[] getContent()
    {
        return content;
    }
}
