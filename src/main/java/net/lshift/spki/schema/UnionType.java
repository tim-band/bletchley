package net.lshift.spki.schema;

import java.util.List;

import net.lshift.spki.convert.Convert;

@Convert.SequenceConverted("union")
public class UnionType implements ConverterDeclaration {
    public final List<Tagged> options;

    public UnionType(List<Tagged> options) {
        this.options = options;
    }
}
