package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.DiscriminatingConverter;
import net.lshift.spki.suiteb.AESKey;
import net.lshift.spki.suiteb.AESPacket;
import net.lshift.spki.suiteb.Signature;

/**
 * Class that sets up conversion for SequenceItem objects.
 * SequenceItem is an interface so it can't be set up when the interface
 * is loaded.
 */
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
