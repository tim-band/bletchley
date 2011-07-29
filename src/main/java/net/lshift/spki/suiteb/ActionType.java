package net.lshift.spki.suiteb;

import net.lshift.spki.convert.Convert;

/**
 * Supertype for something that the application might act on.
 * Doesn't know about any of its subclasses - that's application-specific
 */
@Convert.Discriminated({})
public interface ActionType {
    // Marker interface, no body
}
