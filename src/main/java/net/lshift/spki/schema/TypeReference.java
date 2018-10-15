package net.lshift.spki.schema;

import java.text.MessageFormat;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.sexpform.Sexp;

@Convert.ByPosition(name="ref",fields="name")
public class TypeReference implements Type {
    public final String name;

    public TypeReference(String name) {
        this.name = name;
    }

    public static String name(Class<?> clazz) {
        if(clazz.isArray() && clazz.getComponentType() == Byte.TYPE) {
            return "spki:atom";
        } else if(clazz == Sexp.class) {
            return "spki:expr";
        } else {
            String pkg = clazz.getPackage().getName().replaceFirst("^net.lshift.spki", "spki");
            return MessageFormat.format("{0}:{1}", pkg, clazz.getSimpleName());
        }
    }

    public TypeReference(Class<?> clazz) {
        this(name(clazz));
    }
}
