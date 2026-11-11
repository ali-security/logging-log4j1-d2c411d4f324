/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.log4j.net;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.InvalidObjectException;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;

import org.apache.log4j.Hierarchy;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.VectorAppender;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.RootLogger;

/**
 * Tests for {@link HardenedObjectInputStream} collection count limiting
 * that mitigates CVE-2023-26464.
 *
 * CVE-2023-26464: Deeply nested hash-based collection structures cause
 * exponential hashCode() computation during deserialization, leading
 * to Denial of Service. The fix limits the total number of Map/Collection
 * instances that can be deserialized in a single object graph.
 */
public class HardenedObjectInputStreamTest extends TestCase {

    /**
     * How long a payload may take to deserialize. A vulnerable stream spends
     * hours or more on the attack payloads below, a hardened one milliseconds.
     */
    private static final long TIMEOUT_MILLIS = 30000;

    private byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.close();
        return bos.toByteArray();
    }

    /**
     * Reads one object from payload on a separate thread and returns what the
     * read threw, or null. A read that does not finish in time fails the test
     * instead of hanging it.
     */
    private Throwable readInBackground(final byte[] payload) throws InterruptedException {
        final Throwable[] thrown = new Throwable[1];
        Thread reader = new Thread("HardenedObjectInputStreamTest reader") {
            public void run() {
                try {
                    HardenedObjectInputStream hois = new HardenedObjectInputStream(
                            new ByteArrayInputStream(payload), new String[0]);
                    try {
                        hois.readObject();
                    } finally {
                        hois.close();
                    }
                } catch (Throwable t) {
                    thrown[0] = t;
                }
            }
        };
        reader.setDaemon(true);
        reader.start();
        reader.join(TIMEOUT_MILLIS);
        assertFalse("Deserialization still running after " + TIMEOUT_MILLIS
                + " ms (CVE-2023-26464 denial of service)", reader.isAlive());
        return thrown[0];
    }

    private void assertCollectionLimitExceeded(Throwable thrown) {
        assertTrue("Expected InvalidObjectException, got " + thrown,
                thrown instanceof InvalidObjectException);
        assertTrue("Should mention collection limit",
                thrown.getMessage().indexOf("collection") >= 0);
    }

    /**
     * Builds a HashSet holding Hashtables nested four levels deep where all
     * 1000 values of a table point to the same next table. Only six
     * collections are sent, but hashing the outer table walks 1000^4 paths.
     */
    private Set sharedHashtableFanOut() {
        Set root = new HashSet();
        Hashtable current = new Hashtable();
        // added while empty, so building the payload does not hash it
        root.add(current);
        for (int depth = 0; depth < 4; depth++) {
            Hashtable next = new Hashtable();
            for (int i = 0; i < 1000; i++) {
                current.put("key" + i, next);
            }
            current = next;
        }
        current.put("leaf", "value");
        return root;
    }

    /**
     * CVE-2023-26464: The exact attack payload from the logback advisory.
     * Deeply nested HashSet structures that cause exponential hashCode()
     * computation. The collection count limit must reject this before
     * the computation becomes dangerous.
     */
    public void testDeeplyNestedHashSetRejected() throws Exception {
        // Build the CVE-2023-26464 attack payload: deeply nested HashSets
        // that form a DAG causing O(2^N) hashCode() computation
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < 100; i++) {
            Set t1 = new HashSet();
            Set t2 = new HashSet();
            t1.add("foo");
            s1.add(t1);
            s1.add(t2);
            s2.add(t1);
            s2.add(t2);
            s1 = t1;
            s2 = t2;
        }
        byte[] serialized = serialize(root);

        Throwable thrown = readInBackground(serialized);
        if (thrown instanceof InvalidObjectException) {
            // Our resolveObject-based collection limits caught it
            assertTrue("Should mention collection limit",
                    thrown.getMessage().indexOf("collection") >= 0);
        } else if (!(thrown instanceof InvalidClassException)) {
            // With a JEP 290 serialization filter the depth limit may reject it
            // first with "filter status: REJECTED". Either way, the attack is blocked.
            fail("Deeply nested HashSet should be rejected due to collection count limit, got " + thrown);
        }
    }

    /**
     * A moderate number of nested collections (within the limit) should
     * still be allowed. This tests that normal LoggingEvent-like payloads
     * with a few Hashtables work fine.
     */
    public void testModerateCollectionsAllowed() throws Exception {
        // Simulate a LoggingEvent with MDC (Hashtable) containing a few entries
        Hashtable mdc = new Hashtable();
        mdc.put("user", "alice");
        mdc.put("session", "abc123");
        mdc.put("requestId", "req-456");
        byte[] serialized = serialize(mdc);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        Object result = hois.readObject();
        assertTrue(result instanceof Hashtable);
        assertEquals("alice", ((Hashtable) result).get("user"));
        hois.close();
    }

    /**
     * Simple non-collection objects should work unaffected.
     */
    public void testStringAllowed() throws Exception {
        byte[] serialized = serialize("hello world");

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        assertEquals("hello world", hois.readObject());
        hois.close();
    }

    /**
     * More collections than MAX_COLLECTION_COUNT in one object are rejected.
     */
    public void testTooManyCollectionsRejected() throws Exception {
        List list = new ArrayList();
        for (int i = 0; i < HardenedObjectInputStream.MAX_COLLECTION_COUNT + 8; i++) {
            list.add(new ArrayList());
        }
        Throwable thrown = readInBackground(serialize(list));
        assertCollectionLimitExceeded(thrown);
        assertTrue(thrown.getMessage().indexOf("number of collection objects") >= 0);
    }

    /**
     * A handful of nested Hashtables sharing their values stays below
     * MAX_COLLECTION_COUNT but would still make hashCode() exponential.
     */
    public void testSharedNestedHashtablesRejected() throws Exception {
        Throwable thrown = readInBackground(serialize(sharedHashtableFanOut()));
        assertCollectionLimitExceeded(thrown);
    }

    /**
     * Collections.nCopies is sent as a count and a single element, so three
     * tiny nested copies lists make toString(), e.g. when a layout renders the
     * MDC, and hashCode() on JVMs without a dedicated CopiesList.hashCode(),
     * visit 10000^3 elements.
     */
    public void testNestedCopiesListsRejected() throws Exception {
        List copies = Collections.nCopies(10000,
                Collections.nCopies(10000, Collections.nCopies(10000, "x")));
        List wrapper = new ArrayList();
        Set root = new HashSet();
        // added while empty, so building the payload does not hash it
        root.add(wrapper);
        wrapper.add(copies);

        Throwable thrown = readInBackground(serialize(root));
        assertCollectionLimitExceeded(thrown);
    }

    /**
     * Map.Entry.hashCode() hashes the key and the value: entries whose key and
     * value are the same next entry double the work at every level without
     * any Map or Collection in between.
     */
    public void testSharedNestedMapEntriesRejected() throws Exception {
        Object entry = "leaf";
        for (int i = 0; i < 22; i++) {
            entry = new AbstractMap.SimpleEntry(entry, entry);
        }
        List wrapper = new ArrayList();
        Set root = new HashSet();
        // added while empty, so building the payload does not hash it
        root.add(wrapper);
        for (int i = 0; i < 10000; i++) {
            wrapper.add(entry);
        }

        Throwable thrown = readInBackground(serialize(root));
        assertCollectionLimitExceeded(thrown);
    }

    /**
     * A Hashtable announcing about 10^9 entries would make Hashtable.readObject
     * allocate a multi-gigabyte bucket array before reading any entry; nested
     * ones keep all of those arrays alive. Where the JVM supports JEP 290
     * serialization filters, the array length limit rejects it up front.
     */
    public void testHashtableAnnouncingHugeSizeRejected() throws Exception {
        if (!isSerialFilterAvailable()) {
            // JVMs without serialization filters (before 7u131 and 8u121)
            // offer no hook ahead of that allocation
            return;
        }
        Hashtable table = new Hashtable();
        table.put("key", "value");
        byte[] payload = serialize(table);
        // Hashtable.writeObject writes the bucket array length (11) and the
        // element count (1) as one block: TC_BLOCKDATA, 8, length, count
        int at = indexOf(payload, new byte[] { 0x77, 0x08, 0, 0, 0, 0x0B, 0, 0, 0, 0x01 });
        assertTrue("Hashtable size block not found", at >= 0);
        writeInt(payload, at + 2, Integer.MAX_VALUE - 8);
        writeInt(payload, at + 6, 0x3FFFFFFF);

        Throwable thrown = readInBackground(payload);
        assertTrue("Expected the serialization filter to reject the table, got " + thrown,
                thrown instanceof InvalidClassException);
    }

    /**
     * readAdaptedObject gives every object read from a stream its own budget,
     * so a long-lived connection keeps accepting ordinary events.
     */
    public void testReadAdaptedObjectResetsLimitsPerObject() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        for (int i = 0; i < 3; i++) {
            Hashtable mdc = new Hashtable();
            for (int j = 0; j < 20; j++) {
                List value = new ArrayList();
                value.add("value" + j);
                mdc.put("key" + j, value);
            }
            oos.writeObject(mdc);
            oos.reset();
        }
        oos.close();

        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(bos.toByteArray()), new String[0]);
        for (int i = 0; i < 3; i++) {
            Hashtable mdc = (Hashtable) hois.readAdaptedObject();
            assertEquals(20, mdc.size());
            assertEquals("value7", ((List) mdc.get("key7")).get(0));
        }
        hois.close();
    }

    /**
     * End to end through SocketNode, which receives SocketAppender events: an
     * event whose MDC carries the attack payload closes the connection quickly
     * instead of tying up the receiving thread, while the ordinary event sent
     * before it is still logged.
     */
    public void testSocketNodeRejectsNestedCollectionEvent() throws Exception {
        Logger logger = Logger.getLogger(HardenedObjectInputStreamTest.class);
        Hashtable mdc = new Hashtable();
        mdc.put("user", "alice");
        LoggingEvent ordinary = new LoggingEvent(Logger.class.getName(), logger,
                System.currentTimeMillis(), Level.INFO, "ordinary", "main", null, null, null, mdc);
        Hashtable attackMdc = new Hashtable();
        attackMdc.put("payload", sharedHashtableFanOut());
        LoggingEvent attack = new LoggingEvent(Logger.class.getName(), logger,
                System.currentTimeMillis(), Level.INFO, "attack", "main", null, null, null, attackMdc);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(ordinary);
        oos.reset();
        oos.writeObject(attack);
        oos.reset();
        oos.close();

        Hierarchy hierarchy = new Hierarchy(new RootLogger(Level.DEBUG));
        VectorAppender appender = new VectorAppender();
        hierarchy.getRootLogger().addAppender(appender);
        Thread node = new Thread(new SocketNode(new PayloadSocket(bos.toByteArray()), hierarchy));
        node.setDaemon(true);
        node.start();
        node.join(TIMEOUT_MILLIS);
        assertFalse("SocketNode still reading after " + TIMEOUT_MILLIS
                + " ms (CVE-2023-26464 denial of service)", node.isAlive());

        assertEquals(1, appender.getVector().size());
        LoggingEvent received = (LoggingEvent) appender.getVector().elementAt(0);
        assertEquals("ordinary", received.getRenderedMessage());
        assertEquals("alice", received.getMDC("user"));
    }

    private static boolean isSerialFilterAvailable() {
        String[] filterClasses = new String[] { "java.io.ObjectInputFilter", "sun.misc.ObjectInputFilter" };
        for (int i = 0; i < filterClasses.length; i++) {
            try {
                Class.forName(filterClasses[i]);
                return true;
            } catch (ClassNotFoundException e) {
                // try the next one
            }
        }
        return false;
    }

    private static int indexOf(byte[] data, byte[] pattern) {
        for (int i = 0; i + pattern.length <= data.length; i++) {
            int j = 0;
            while (j < pattern.length && data[i + j] == pattern[j]) {
                j++;
            }
            if (j == pattern.length) {
                return i;
            }
        }
        return -1;
    }

    private static void writeInt(byte[] data, int offset, int value) {
        data[offset] = (byte) (value >>> 24);
        data[offset + 1] = (byte) (value >>> 16);
        data[offset + 2] = (byte) (value >>> 8);
        data[offset + 3] = (byte) value;
    }

    /** A socket whose input is a fixed byte array, as if sent by a SocketAppender. */
    private static final class PayloadSocket extends Socket {
        private final InputStream input;

        PayloadSocket(byte[] payload) {
            this.input = new ByteArrayInputStream(payload);
        }

        public InputStream getInputStream() {
            return input;
        }
    }
}
