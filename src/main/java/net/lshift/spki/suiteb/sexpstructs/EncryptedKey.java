package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.P;
import net.lshift.spki.convert.PositionBeanConvertable;
import net.lshift.spki.convert.SExpName;

/**
 * Serialization format for a symmetric key
 *
 * FIXME: EncryptedKey isn't a good name for this class
 */
public class EncryptedKey
    extends PositionBeanConvertable
{
    private final byte[] key;

    @SExpName("suiteb-aes-gcm-key")
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
