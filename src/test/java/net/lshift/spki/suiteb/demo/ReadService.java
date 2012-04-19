package net.lshift.spki.suiteb.demo;

import java.io.IOException;

import net.lshift.spki.InvalidInputException;
import net.lshift.spki.convert.openable.Openable;
import net.lshift.spki.convert.openable.OpenableUtils;

public class ReadService {
    public static Service readService(Openable source)
                    throws IOException, InvalidInputException {
        return OpenableUtils.read(Service.class, source);
    }
}
