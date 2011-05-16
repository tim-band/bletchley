package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertable;
import net.lshift.spki.convert.SExpName;

public class EncryptedKey
    extends PositionBeanConvertable
{
    private final byte[] key;

    @SExpName("suiteb-encrypted-key")
    public EncryptedKey(
        @P("key") byte[] key
    ) {
        super();
        this.key = key;
    }

    public byte[] getKey()
    {
        return key;
    }
}
