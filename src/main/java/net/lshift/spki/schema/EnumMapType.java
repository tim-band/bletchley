package net.lshift.spki.schema;

import java.util.List;

import net.lshift.spki.convert.Convert;

@Convert.SequenceConverted("enum-map")
public class EnumMapType
        implements ConverterDeclaration {
    public final List<Field> fields;

    public EnumMapType(List<Field> fields) {
        super();
        this.fields = fields;
    }
}
