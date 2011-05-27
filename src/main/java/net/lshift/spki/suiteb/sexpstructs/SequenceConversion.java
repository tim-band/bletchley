package net.lshift.spki.suiteb.sexpstructs;

import net.lshift.spki.convert.DiscriminatingConverter;
import net.lshift.spki.convert.Registry;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.AesPacket;
import net.lshift.spki.suiteb.Signature;

/**
 * Class that sets up conversion for SequenceItem objects.
 * SequenceItem is an interface so it can't be set up when the interface
 * is loaded.
 */
@SuppressWarnings("unchecked")
public class SequenceConversion {
    static {
        Registry.REGISTRY.register(SequenceItem.class,
            new DiscriminatingConverter<SequenceItem>(
                Sequence.class,
                EcdhItem.class,
                AesPacket.class,
                AesKey.class,
                SimpleMessage.class,
                EcdsaPublicKey.class,
                Signature.class,
                Hash.class));
    }

    public static void ensureInstalled() {
        // Initialize the class
    }
}
