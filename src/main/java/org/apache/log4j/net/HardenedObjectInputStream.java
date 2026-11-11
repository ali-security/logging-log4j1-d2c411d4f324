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

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.ArrayList;
import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * HardenedObjectInputStream restricts the set of classes that can be
 * deserialized to a set of explicitly whitelisted classes. This prevents
 * certain type of attacks from being successful.
 * 
 * <p>
 * It is assumed that classes in the "java.lang" and "java.util" packages are
 * always authorized.
 * </p>
 * 
 * @author Ceki G&uuml;lc&uuml;
 * @since 1.2.18
 * 
 *        === Copied from the logback project with permission ==
 */
public class HardenedObjectInputStream extends ObjectInputStream {

	static final String ARRAY_CLASS_PREFIX = "[L";
	final List whitelistedClassNames;
	final static String[] JAVA_PACKAGES = new String[] { "java.lang", "java.util", ARRAY_CLASS_PREFIX + "java.lang" };

	/**
	 * Maximum number of Map/Collection instances allowed during deserialization
	 * of a single object graph. This mitigates CVE-2023-26464 where deeply
	 * nested hash-based collections cause exponential hashCode() computation.
	 *
	 * With N collection objects, the worst-case hashCode cost is O(2^(N/2)).
	 * A limit of 32 bounds this to O(2^16) = ~65K operations.
	 * A normal LoggingEvent has 1-2 collections (MDC Hashtable, properties).
	 */
	static final int MAX_COLLECTION_COUNT = 32;

	/**
	 * Maximum number of elements that hashCode() or toString() of a single
	 * deserialized Map, Collection or Map.Entry may visit, counting
	 * every path through shared (back-referenced) elements. Unlike
	 * {@link #MAX_COLLECTION_COUNT} this also bounds a few collections that
	 * reference each other many times, e.g. a handful of nested Hashtables
	 * whose values all point to the next one (CVE-2023-26464).
	 */
	static final int MAX_COLLECTION_COST = 1 << 16;

	/**
	 * Maximum depth of the object graph of a single deserialized object,
	 * enforced through a JEP 290 serialization filter where the JVM has one.
	 */
	static final int MAX_DEPTH = 32;

	/**
	 * Maximum length of an array, including the bucket arrays Hashtable and
	 * HashMap pre-allocate from the size announced in the stream, enforced
	 * through a JEP 290 serialization filter where the JVM has one.
	 */
	static final int MAX_ARRAY_LENGTH = 1 << 16;

	private static final Long UNIT_COST = new Long(1);

	private int collectionCount = 0;

	/**
	 * Cost (see {@link #MAX_COLLECTION_COST}) of the Map, Collection and
	 * Map.Entry instances read so far, keyed by identity.
	 */
	private final Map collectionCosts = new IdentityHashMap();

	public HardenedObjectInputStream(InputStream in, String[] whilelist) throws IOException {
		super(in);
		enableResolveObject(true);
		installSerialFilter();

		this.whitelistedClassNames = new ArrayList();
		if (whilelist != null) {
			for (int i = 0; i < whilelist.length; i++) {
				this.whitelistedClassNames.add(whilelist[i]);
			}
		}
	}

	public HardenedObjectInputStream(InputStream in, List whitelist) throws IOException {
		super(in);
		enableResolveObject(true);
		installSerialFilter();

		this.whitelistedClassNames = new ArrayList();
		this.whitelistedClassNames.addAll(whitelist);
	}

	/**
	 * Limits the depth of the object graph and the length of arrays through a
	 * JEP 290 serialization filter (Java 9+, or the sun.misc variant of Java
	 * 8u121+ and 7u131+). Collections check the length of the arrays they
	 * pre-allocate against the filter before allocating them, so nested
	 * Hashtables or HashMaps announcing huge sizes cannot exhaust the heap
	 * (CVE-2023-26464). A filter already configured for the stream, e.g. via
	 * the jdk.serialFilter system property, is left in place. Older JVMs have
	 * no such filter and rely on {@link #resolveObject(Object)} alone.
	 */
	private void installSerialFilter() {
		String limits = "maxdepth=" + MAX_DEPTH + ";maxarray=" + MAX_ARRAY_LENGTH;
		Class[] noTypes = new Class[0];
		Object[] noArgs = new Object[0];
		try {
			Class filterClass = Class.forName("java.io.ObjectInputFilter");
			if (ObjectInputStream.class.getMethod("getObjectInputFilter", noTypes).invoke(this, noArgs) == null) {
				Object filter = Class.forName("java.io.ObjectInputFilter$Config")
						.getMethod("createFilter", new Class[] { String.class }).invoke(null, new Object[] { limits });
				ObjectInputStream.class.getMethod("setObjectInputFilter", new Class[] { filterClass })
						.invoke(this, new Object[] { filter });
			}
			return;
		} catch (ClassNotFoundException e) {
			// before Java 9, try the sun.misc variant below
		} catch (Exception e) {
			return;
		}
		try {
			Class filterClass = Class.forName("sun.misc.ObjectInputFilter");
			Class configClass = Class.forName("sun.misc.ObjectInputFilter$Config");
			if (configClass.getMethod("getObjectInputFilter", new Class[] { ObjectInputStream.class })
					.invoke(null, new Object[] { this }) == null) {
				Object filter = configClass.getMethod("createFilter", new Class[] { String.class })
						.invoke(null, new Object[] { limits });
				configClass.getMethod("setObjectInputFilter", new Class[] { ObjectInputStream.class, filterClass })
						.invoke(null, new Object[] { this, filter });
			}
		} catch (Exception e) {
			// no serialization filter support in this JVM
		}
	}

	protected Class resolveClass(ObjectStreamClass anObjectStreamClass) throws IOException, ClassNotFoundException {

		String incomingClassName = anObjectStreamClass.getName();

		if (!isWhitelisted(incomingClassName)) {
			throw new InvalidClassException("Unauthorized deserialization attempt", incomingClassName);
		}

		return super.resolveClass(anObjectStreamClass);
	}

	private boolean isWhitelisted(String incomingClassName) {
		for (int i = 0; i < JAVA_PACKAGES.length; i++) {
			if (incomingClassName.startsWith(JAVA_PACKAGES[i]))
				return true;
		}
		for (int i = 0; i < whitelistedClassNames.size(); i++) {
			String whiteListed = (String) whitelistedClassNames.get(i);
			if (incomingClassName.equals(whiteListed))
				return true;
		}
		return false;
	}

	/**
	 * Reads an object from the stream, resetting the collection counter
	 * so that each top-level readObject call gets its own budget.
	 * Callers should use this instead of {@link #readObject()} directly
	 * when reading multiple objects from the same stream.
	 */
	public Object readAdaptedObject() throws IOException, ClassNotFoundException {
		collectionCount = 0;
		collectionCosts.clear();
		return readObject();
	}

	/**
	 * Counts Map and Collection instances during deserialization to prevent
	 * CVE-2023-26464: deeply nested hash-based collections cause exponential
	 * hashCode() computation during deserialization.
	 *
	 * <p>
	 * Each Map, Collection and Map.Entry is resolved once its content has been
	 * read, but before an enclosing hash-based collection calls its hashCode().
	 * Its cost (see {@link #MAX_COLLECTION_COST}) is checked at that point.
	 * </p>
	 */
	protected Object resolveObject(Object obj) throws IOException {
		if (obj instanceof Map || obj instanceof Collection) {
			collectionCount++;
			if (collectionCount > MAX_COLLECTION_COUNT) {
				throw new InvalidObjectException(
					"Exceeded maximum number of collection objects during deserialization: "
					+ MAX_COLLECTION_COUNT
					+ ". Possible CVE-2023-26464 attack via nested collections.");
			}
		}
		if (isCollectionLike(obj)) {
			// a reference back to obj from its own content counts as one element
			collectionCosts.put(obj, UNIT_COST);
			long cost = computeCost(obj);
			if (cost > MAX_COLLECTION_COST) {
				throw new InvalidObjectException(
					"Exceeded maximum cost of collection objects during deserialization: "
					+ MAX_COLLECTION_COST
					+ ". Possible CVE-2023-26464 attack via nested collections.");
			}
			collectionCosts.put(obj, new Long(cost));
		}
		return super.resolveObject(obj);
	}

	private static boolean isCollectionLike(Object obj) {
		return obj instanceof Map || obj instanceof Collection || obj instanceof Map.Entry;
	}

	/**
	 * Returns the number of elements visited when walking obj, counting obj
	 * itself. Stops early once {@link #MAX_COLLECTION_COST} is exceeded so that
	 * huge or self-multiplying collections are not walked in full.
	 */
	private long computeCost(Object obj) {
		long cost = 1;
		if (obj instanceof Map) {
			Iterator entries = ((Map) obj).entrySet().iterator();
			while (cost <= MAX_COLLECTION_COST && entries.hasNext()) {
				Map.Entry entry = (Map.Entry) entries.next();
				cost += costOf(entry.getKey()) + costOf(entry.getValue());
			}
		} else if (obj instanceof Collection) {
			Iterator elements = ((Collection) obj).iterator();
			while (cost <= MAX_COLLECTION_COST && elements.hasNext()) {
				cost += costOf(elements.next());
			}
		} else {
			Map.Entry entry = (Map.Entry) obj;
			cost += costOf(entry.getKey()) + costOf(entry.getValue());
		}
		return cost;
	}

	private long costOf(Object element) {
		if (!isCollectionLike(element)) {
			return 1;
		}
		Long known = (Long) collectionCosts.get(element);
		if (known != null) {
			return known.longValue();
		}
		// Not resolved during the current read: a reference to an enclosing
		// object that is still being read, or to an object read earlier from
		// this stream. Measure it now; cycles stop at the provisional unit cost.
		collectionCosts.put(element, UNIT_COST);
		long cost;
		try {
			cost = computeCost(element);
		} catch (RuntimeException e) {
			// an enclosing object may not be fully initialized yet
			cost = 1;
		}
		cost = Math.min(cost, MAX_COLLECTION_COST + 1L);
		collectionCosts.put(element, new Long(cost));
		return cost;
	}

	protected void addToWhitelist(List additionalAuthorizedClasses) {
		whitelistedClassNames.addAll(additionalAuthorizedClasses);
	}
}