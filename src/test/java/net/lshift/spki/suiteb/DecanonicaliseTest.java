package net.lshift.spki.suiteb;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.Test;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.google.protobuf.CodedOutputStream;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.UsesSimpleMessage;
import net.lshift.spki.suiteb.DecanonicaliseProto.ExampleAction;
import net.lshift.spki.suiteb.DecanonicaliseProto.ExampleActionExtraField;

public class DecanonicaliseTest extends UsesSimpleMessage {
    
    private static final String FULL_NAME = ExampleAction.getDescriptor().getFullName();
    private static final String EXTRA_FIELD_FULL_NAME = ExampleActionExtraField.getDescriptor().getFullName();
    private static final SequenceItemConverter CONVERTER = new SequenceItemConverter(ExampleAction.class, ExampleActionExtraField.class);
    private static final int BUFFER_CAPACITY = 4096;

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
    
    @Test
    public void digestReversedFieldsTest() throws IOException, InvalidInputException {
        ExampleAction exampleAction = ExampleAction.newBuilder().setA("foo").setB("bar").build();
        Action exampleSequenceItemOriginal = SequenceUtils.action(exampleAction);
        Action exampleSequenceItemRebuilt = CONVERTER
                .parse(actionSequenceItemWithReversedFields(exampleAction))
                .require(Action.class);
        // If fields get re-ordered on the wire, the digest should be unchanged.
        assertEquals(
                DigestSha384.digest(exampleSequenceItemOriginal), 
                DigestSha384.digest(exampleSequenceItemRebuilt));
    }

    @Test
    public void digestUnknownFieldTest() throws IOException, InvalidInputException {
        ExampleActionExtraField exampleActionExtra = ExampleActionExtraField.newBuilder().setA("foo").setB("bar").setC("baz").build();
        Action exampleSequenceItemOriginal = SequenceUtils.action(exampleActionExtra);
        // What we expect is that if field is known - I.e. the the action is labelled with the right type
        // the round trip will produce the same digest. Think of this assert as the control
        assertEquals(
                DigestSha384.digest(exampleSequenceItemOriginal), 
                DigestSha384.digest(CONVERTER
                        .parse(actionSequenceItemToBytes(EXTRA_FIELD_FULL_NAME, exampleActionExtra.toByteString()))
                        .require(Action.class)));
        // If we label the action with a type that has one less field, the round trip will produce different digests
        // This is what we want - because if we don't understand the whole content of a message, we don't want
        // to accept it. It might mean something different to the sender/signer
        assertNotEquals(
                DigestSha384.digest(exampleSequenceItemOriginal), 
                DigestSha384.digest(CONVERTER
                        .parse(actionSequenceItemToBytes(FULL_NAME, exampleActionExtra.toByteString()))
                        .require(Action.class)));
        // This doesn't go on to prove a signature would fail: that's tested elsewhere.
    }
    
    private void writeExampleActionReversedFields(
            ExampleAction exampleAction, 
            CodedOutputStream output)
                    throws IOException {
        if (!exampleAction.getBBytes().isEmpty()) {
            output.writeString(2, exampleAction.getB()) ;
        }
        if (!exampleAction.getABytes().isEmpty()) {
            output.writeString(1, exampleAction.getA());
        }
        exampleAction.getUnknownFields().writeTo(output);
    }
    
    private ByteString actionWithReversedFieldsToBytes(ExampleAction exampleAction) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(BUFFER_CAPACITY);
        CodedOutputStream output = CodedOutputStream.newInstance(buffer);
        writeExampleActionReversedFields(exampleAction, output);
        output.flush();
        return ByteString.copyFrom(buffer.toByteArray());
    }
    
    private ByteString actionSequenceItemWithReversedFields(ExampleAction exampleAction) throws IOException {
        return actionSequenceItemToBytes(FULL_NAME, actionWithReversedFieldsToBytes(exampleAction));
    }

    private ByteString actionSequenceItemToBytes(String fullName, ByteString actionBytes) {
        return SuiteBProto.SequenceItem.newBuilder()
                .setAction(SuiteBProto.Action.newBuilder()
                        .setAccept(Any.newBuilder()
                                .setTypeUrl(Action.typeUrl(fullName))
                                .setValue(actionBytes)))
                .build()
                .toByteString();
    }
}
