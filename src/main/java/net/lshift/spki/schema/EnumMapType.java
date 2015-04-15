package net.lshift.spki.schema;

import java.util.List;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.SexpBacked;

@Convert.SequenceConverted("enum-map")
public class EnumMapType 
extends SexpBacked 
implements ConverterDeclaration {
    public final List<Field> fields;

    public EnumMapType(List<Field> fields) {
        super();
        this.fields = fields;
    }
}
