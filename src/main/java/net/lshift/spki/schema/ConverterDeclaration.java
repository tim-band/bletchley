package net.lshift.spki.schema;

import net.lshift.spki.convert.Convert;

@Convert.Discriminated({
    AtomType.class,
    UnionType.class,
    EnumMapType.class,
    TupleType.class,
    VariadicType.class,
    Vector.class,
    ExprType.class,
    Restriction.class})
public interface ConverterDeclaration {

}
