package net.lshift.spki.schema;

import java.util.List;

import net.lshift.spki.convert.Convert;

@Convert.SequenceConverted("tuple")
public class TupleType
        implements ConverterDeclaration {
    public final List<Field> fields;

    public TupleType(List<Field> fields) {
        this.fields = fields;
    }
}
