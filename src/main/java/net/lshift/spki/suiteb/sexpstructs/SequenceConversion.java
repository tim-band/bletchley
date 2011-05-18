package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.DiscriminatingConverter;
import net.lshift.spki.suiteb.AESKey;
import net.lshift.spki.suiteb.AESPacket;
import net.lshift.spki.suiteb.Signature;

@SuppressWarnings("unchecked")
public class SequenceConversion
{
    static {
        Convert.REGISTRY.register(SequenceItem.class,
            new DiscriminatingConverter<SequenceItem>(
                Sequence.class,
                ECDHItem.class,
                AESPacket.class,
                AESKey.class,
                SimpleMessage.class,
                ECDSAPublicKey.class,
                Signature.class));
    }

    public static void ensureInstalled() {
        // Initialize the class
    }
}
