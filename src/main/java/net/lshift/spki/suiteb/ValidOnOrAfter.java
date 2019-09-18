package net.lshift.spki.suiteb;

import static net.lshift.spki.suiteb.InferenceVariables.NOW;

import java.util.Date;

import com.google.protobuf.Message;

import net.lshift.bletchley.suiteb.proto.SuiteBProto;
import net.lshift.spki.suiteb.proto.ProtobufHelper;

/**
 * Valid only on or after the date given -
 * fails before that date.
 */
public class ValidOnOrAfter implements Condition {
    public final Date date;

    public ValidOnOrAfter(final Date date) {
        this.date = date;
    }

    @Override
    public boolean allows(
            final InferenceEngine engine, 
            final Message action) {
        return !NOW.get(engine).before(date);
    }

    @Override
    public SuiteBProto.Condition.Builder toProtobuf() {
        return SuiteBProto.Condition.newBuilder().setValidOnOrAfter(
                SuiteBProto.ValidOnOrAfterCondition.newBuilder()
                .setDate(ProtobufHelper.fromDate(date)));
    }
}
