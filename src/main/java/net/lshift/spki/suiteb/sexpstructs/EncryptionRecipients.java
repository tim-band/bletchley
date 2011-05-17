package net.lshift.spki.suiteb.sexpstructs;

import java.util.List;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SExpName;
import net.lshift.spki.convert.SequenceConvertable;

public class EncryptionRecipients extends SequenceConvertable
{
    private final List<ECDHMessage> recipients;

    @SExpName("recipients")
    public EncryptionRecipients(
        @P("recipients") List<ECDHMessage> recipients)
    {
        super();
        this.recipients = recipients;
    }

    public List<ECDHMessage> getRecipients()
    {
        return recipients;
    }
}
