package net.lshift.spki.schema;

import java.util.List;

import net.lshift.spki.convert.Convert;

/**
 * This type accepts the first n expressions like a tuple.
 * The remaining elements must satisfy the componentType. Basically
 * it's a tuple followed by an inlined vector. This roughly corresponds
 * to a variadic function in Java.
 */
@Convert.ByPosition(name="variadic",fields={"fields","componentType"})
public class VariadicType 
extends Vector
implements ConverterDeclaration {
    public final EnumMapType fields;

    public VariadicType(
            List<Field> fields,
            Type memberType) {
        super(memberType);
        this.fields = new EnumMapType(fields);
    }
}
