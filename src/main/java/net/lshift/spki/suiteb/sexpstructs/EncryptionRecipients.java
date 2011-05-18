package net.lshift.spki.suiteb.sexpstructs;

import java.util.List;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SExpName;
import net.lshift.spki.convert.SequenceConvertable;

/**
 * A list of messages for multiple distinct recipients
 */
public class EncryptionRecipients extends SequenceConvertable
{
    public final List<ECDHMessage> recipients;

    @SExpName("recipients")
    public EncryptionRecipients(
        @P("recipients") List<ECDHMessage> recipients)
    {
        super();
        this.recipients = recipients;
    }
}
