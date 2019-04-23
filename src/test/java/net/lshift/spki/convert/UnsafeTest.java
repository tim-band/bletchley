package net.lshift.spki.convert;

import static org.apache.commons.lang.builder.EqualsBuilder.reflectionEquals;
import static org.apache.commons.lang.builder.HashCodeBuilder.reflectionHashCode;
import static org.apache.commons.lang.builder.ToStringBuilder.reflectionToString;
import static org.junit.Assert.assertEquals;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import sun.misc.Unsafe;

@SuppressWarnings("restriction")
public class UnsafeTest {
    public static class TestClass {
        public final BigInteger foo;
        public final int bar;

        public TestClass(final BigInteger foo, final int bar) {
            this.foo = foo;
            this.bar = bar;
        }

        @Override public String toString() { return reflectionToString(this); }
        @Override public int hashCode() { return reflectionHashCode(this); }
        @Override public boolean equals(final Object obj) {
            return reflectionEquals(this, obj);
        }

    }

    @Test
    public void listFields() throws Exception {
        Class<?> clazz = TestClass.class;
        while (clazz != null) {
            System.out.println("============ " + clazz.getCanonicalName());
            for (final Field field: clazz.getDeclaredFields()) {
                System.out.println(field.getName());
                System.out.println(field.getType().getCanonicalName());
                System.out.println(field.getModifiers() & Modifier.TRANSIENT);
            }
            clazz = clazz.getSuperclass();
        }
    }

    @Test
    public void canAccessUnsafe() throws Exception {
        final TestClass start = new TestClass(BigInteger.valueOf(3), 4);
        Unsafe unsafe = null;
        final Field field = Unsafe.class.getDeclaredField("theUnsafe");
        field.setAccessible(true);
        unsafe = (Unsafe) field.get(null);
        final Class<TestClass> clazz = TestClass.class;
        final Object p = unsafe.allocateInstance(clazz);

        final Field fooField = clazz.getDeclaredField("foo");
        fooField.setAccessible(true);
        fooField.set(p, start.foo);
        final Field barField = clazz.getDeclaredField("bar");
        barField.setAccessible(true);
        barField.setInt(p, start.bar);
        assertEquals(start, p);
    }

    @Test
    public void callDeserializationConstructor() throws Exception {
        final TestClass start = new TestClass(BigInteger.valueOf(3), 4);
        final Map<Field, Object> fields = new HashMap<Field,Object>();
        fields.put(TestClass.class.getDeclaredField("foo"), start.foo);
        fields.put(TestClass.class.getDeclaredField("bar"), start.bar);
        final TestClass copy = DeserializingConstructor.make(TestClass.class, fields);
        assertEquals(start, copy);
    }
}
