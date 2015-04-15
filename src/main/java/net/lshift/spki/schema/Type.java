package net.lshift.spki.schema;

import net.lshift.spki.convert.Convert;

@Convert.Discriminated({
    TypeReference.class, 
    ListType.class})
public interface Type {

}
