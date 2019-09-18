package net.lshift.spki.convert;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import com.google.protobuf.Message;

/**
 * Map between Bletchley's internal classes and the protobuf representation.
 * Internal classes implement a converter to the protocol buffer representation
 * and are annotated with the protocol buffer representation class. 
 * @param <B>
 */
public interface ProtobufConvertible<B extends Message.Builder> {
    @Retention(RetentionPolicy.RUNTIME)
    public @interface ProtobufClass {
        Class<?> value();
    }
    
    B toProtobuf();
}
