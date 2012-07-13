package net.lshift.spki.convert;

@Convert.Discriminated({ImplementingClass.class, OtherImplementingClass.class})
public interface Interface extends Writeable
{
    // Marker interface, no body
}
