package net.lshift.spki.schema;

import net.lshift.spki.convert.Convert;

/* The name of this class and the field name
 * is chosen to match XSD: I.e. the created type is a simple
 * type which is a restriction of a base simple type.
 */
@Convert.ByPosition(name="restriction", fields="base")
public class Restriction
        implements ConverterDeclaration {
    public final TypeReference base;

    public Restriction(TypeReference parent) {
        this.base = parent;
    }

    public Restriction(Class<?> stepClass) {
        this(new TypeReference(stepClass));
    }
}
