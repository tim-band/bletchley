package net.lshift.spki.suiteb;

import net.lshift.spki.convert.Convert;
import net.lshift.spki.suiteb.sexpstructs.SimpleMessage;

@Convert.Discriminated({
    SimpleMessage.class
})
public interface ActionType {
    // Marker interface, no body
}
