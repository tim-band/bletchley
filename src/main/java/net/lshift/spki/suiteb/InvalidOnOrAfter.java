package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.InferenceVariables.NOW;

import java.util.Date;

import com.google.protobuf.Message;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.suiteb.proto.ProtobufHelper;

/**
 * Valid only strictly before the date given -
 * fails on or after that date.
 */
public class InvalidOnOrAfter implements Condition {
    public final Date date;

    public InvalidOnOrAfter(final Date date) {
        this.date = date;
    }

    @Override
    public boolean allows(final InferenceEngine engine, final Message action) {
        return NOW.get(engine).before(date);
    }
    
    @Override
    public SuiteBProto.Condition.Builder toProtobuf() {
        return SuiteBProto.Condition.newBuilder().setInvalidOnOrAfter(
                SuiteBProto.InvalidOnOrAfterCondition.newBuilder()
                .setDate(ProtobufHelper.fromDate(date)));
    }
}
