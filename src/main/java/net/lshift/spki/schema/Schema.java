package net.lshift.spki.schema;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Stack;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.convert.Converter;
import net.lshift.spki.convert.ConverterCache;
import net.lshift.spki.convert.ConverterCatalog;
import net.lshift.spki.convert.SexpBacked;

@Convert.SequenceConverted("schema")
public class Schema extends SexpBacked {
    public final List<Binding> bindings;

    public Schema(List<Binding> bindings) {
        this.bindings = bindings;
    }

    public static Schema schema(ConverterCatalog catalog, Class<?> ... roots) {
        Stack<Class<?>> unprocessed = new Stack<Class<?>>();
        Set<Class<?>> visited = new HashSet<Class<?>>();
        List<Binding> bindings = new ArrayList<Binding>();
        unprocessed.addAll(Arrays.asList(roots));
        while(!unprocessed.isEmpty()) {
            Class<?> next = unprocessed.pop();
            if(!visited.contains(next)) {
                Converter<?> converter = ConverterCache.getConverter(next);
                bindings.add(new Binding(
                        TypeReference.name(next),
                        converter.declaration()));
                unprocessed.addAll(converter.references());
                visited.add(next);
            }
        }
        return new Schema(bindings);
    }
}