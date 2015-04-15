package net.lshift.spki.schema;

import java.util.List;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.SexpBacked;

@Convert.SequenceConverted("tuple")
public class TupleType 
extends SexpBacked 
implements ConverterDeclaration {
    public final List<Field> fields;

    public TupleType(List<Field> fields) {
        this.fields = fields;
    }
}
