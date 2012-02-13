package net.lshift.spki.convert;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;

/**
 * Extend the idea of the StepConverter to ListConverter in the
 * obvious way.
 */
public abstract class ListStepConverter<TResult, TStep>
extends StepConverter<TResult, TStep>
implements ListConverter<TResult> {
    protected ListConverter<TStep> getStepConverter() {
        return (ListConverter<TStep>)Registry.getConverter(getStepClass());
    }

    @Override
    public String getName() {
        return getStepConverter().getName();
    }

    @Override
    public TResult readRest(ConvertInputStream in) throws IOException,
            InvalidInputException {
        return stepOut(in.readRest(getStepClass()));
    }
}
