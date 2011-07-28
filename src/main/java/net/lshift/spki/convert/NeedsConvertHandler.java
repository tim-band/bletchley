package net.lshift.spki.convert;

import net.lshift.spki.convert.Convert.NeedsConvert;

public class NeedsConvertHandler
implements AnnotationHandler<Convert.NeedsConvert>
{
    @Override
    public void handle(Class<?> clazz, NeedsConvert annotation) {
        Registry.getConverter(annotation.value());
    }
}
