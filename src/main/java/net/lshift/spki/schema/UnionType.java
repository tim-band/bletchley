package net.lshift.spki.schema;

import java.util.List;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.SexpBacked;

@Convert.SequenceConverted("union")
public class UnionType extends SexpBacked implements ConverterDeclaration {
    public final List<Tagged> options;

    public UnionType(List<Tagged> options) {
        super();
        this.options = options;
    }
}
