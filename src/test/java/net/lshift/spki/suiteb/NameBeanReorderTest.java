package net.lshift.spki.suiteb;

import net.lshift.spki.convert.UsesSimpleMessage;

public class NameBeanReorderTest extends UsesSimpleMessage {
    
    /*
        The previous version of this test - for s-expressions
        used Point (EC point) as an example. That's because 
        ECPoints where encoded using named fields, E.g. 
        (point (x ...) (y ...)). So (point (y ...) (x ...)) means 
        the same thing. The code normalises before generating 
        a digest, so they have the same digest as well.
        
        Protocol buffers numbers all fields, and in the encoding,
        always labels fields with those numbers, and the new 
        protocol buffers version also normalises before generating
        a digest, so an equivalent property can be tested in the new
        protocol buffer version.
        
        ECpoints isn't a complete example, because Bletchley
        converts from protocol buffers generated classes
        to it's own representation, and then in the reverse
        conversion, it generates completely new protocol buffers
        objects. What we want to prove is that when you parse a
        de-normalised protocol buffer into a generated object,
        reversing the process produces a normalised protocol
        buffer. For that we need an action.
        
        In addition, protocol buffers retains any fields it
        doesn't understand in a map. It writes the fields it
        understands in order, and then the fields it doesn't
        understand, in order. When a field is added or removed
        from the schema, it's default position in the message changes.
        
        This library is meant to not trust messages it doesn't
        completely understand - we want to discard unknown fields
        when we parse protocol buffers.
     */
    

}
