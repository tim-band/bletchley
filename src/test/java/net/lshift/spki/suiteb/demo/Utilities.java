package net.lshift.spki.suiteb.demo;

import static net.lshift.spki.convert.openable.OpenableUtils.write;
import static net.lshift.spki.suiteb.SequenceUtils.sequence;

import java.io.IOException;

import net.lshift.spki.convert.ReadInfo;
import net.lshift.spki.convert.openable.ByteOpenable;

public class Utilities {
    public static final ReadInfo R = ReadInfo.BASE.extend(Service.class);

    public static ByteOpenable emptyByteOpenable() {
        try {
            ByteOpenable res = new ByteOpenable();
            write(res, sequence());
            return res;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
