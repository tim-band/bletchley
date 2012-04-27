package net.lshift.spki.convert;


/**
 * Extend the idea of the StepConverter to ListConverter in the
 * obvious way.
 */
public abstract class ListStepConverter<TResult, TStep>
extends StepConverter<TResult, TStep>
implements ListConverter<TResult> {
    public ListStepConverter(final Class<TResult> clazz) {
        super(clazz);
    }

    protected ListConverter<TStep> getStepConverter() {
        return (ListConverter<TStep>)Registry.getConverter(getStepClass());
    }

    @Override
    public String getName() {
        return getStepConverter().getName();
    }
}
