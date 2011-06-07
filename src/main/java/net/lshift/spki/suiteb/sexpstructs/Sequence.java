package net.lshift.spki.suiteb.sexpstructs;

import java.security.Signature;
import java.util.List;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.P;
import net.lshift.spki.convert.SexpName;
import net.lshift.spki.convert.SequenceConvertible;
import net.lshift.spki.suiteb.AesKey;
import net.lshift.spki.suiteb.AesPacket;



/**
 * A list of SequenceItems.  Itself a SequenceItem.
 */
@Convert.Discriminated({Sequence.class,
    EcdhItem.class,
    AesPacket.class,
    AesKey.class,
    SimpleMessage.class,
    EcdsaPublicKey.class,
    Signature.class,
    Hash.class})
public class Sequence
    extends SequenceConvertible
    implements SequenceItem {
    public final List<SequenceItem> sequence;

    @SexpName("sequence")
    public Sequence(@P("sequence") List<SequenceItem> sequence) {
        super();
        this.sequence = sequence;
    }
}
