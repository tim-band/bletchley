package net.lshift.spki.convert;


/**
 * Extend the idea of the StepConverter to ListConverter in the
 * obvious way.
 */
public abstract class ListStepConverter<TResult, TStep>
extends StepConverter<TResult, TStep>
implements ListConverter<TResult> {
    public ListStepConverter(final Class<TResult> clazz, final Class<TStep> stepClazz) {
        super(clazz, stepClazz);
    }

    protected ListConverter<TStep> getStepConverter() {
        return (ListConverter<TStep>)ConverterCache.getConverter(stepClazz);
    }

    @Override
    public String getName() {
        return getStepConverter().getName();
    }
}
