package net.sf.michaelo.dirctxsrc.ad;

import java.util.Arrays;
import java.util.Hashtable;
import java.util.Random;
import java.util.Scanner;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.InvalidNameException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;

/**
 * A locator for various Active Directory services like LDAP, Global Catalog, Kerberos, etc. via DNS
 * SRV RRs. This is a lightweight implementation of
 * <a href="http://www.rfc-editor.org/info/rfc2782">RFC 2782<a> for the resource records depicted
 * <a href="https://technet.microsoft.com/en-us/library/cc759550%28v=ws.10%29.aspx">here</a>, but
 * with the limitation that only TCP is queried and the {@code _msdcs} subdomain is ignored. The
 * server selection algorithm for failover is fully implemented.
 * <p>
 * Here is a minimal example how to create an {@code ActiveDirectoryServiceLocator} with the
 * supplied builder:
 *
 * <pre>
 * ActiveDirectoryServiceLocator.Builder builder = new DirContextSource.Builder();
 * ActiveDirectoryServiceLocator locator = builder.build();
 * HostPort servers = locator.locate("ldap", "example.com");
 * </pre>
 *
 * An {@code ActiveDirectoryServiceLocator} object will be initially preconfigured by its builder
 * for you:
 * <ol>
 * <li>The context factory is set by default to {@code com.sun.jndi.dns.DnsContextFactory}.</li>
 * <li>By default the maximum amount of backup servers is set to one which means that at least two
 * servers, main and backup will be returned, if the DNS server returns at least two records.</li>
 * </ol>
 *
 * A complete overview of all {@code DirContext} properties can be found
 * <a href= "https://docs.oracle.com/javase/7/docs/technotes/guides/jndi/jndi-dns.html">here</a>.
 * Make sure that you pass reasonable/valid values only otherwise the behavior is undefined.
 *
 * @version $Id$
 */
public class ActiveDirectoryServiceLocator {

	private static class SrvRecord implements Comparable<SrvRecord> {

		static final String UNVAILABLE_SERVICE = ".";

		private int priority;
		private int weight;
		private int sum;
		private int port;
		private String target;

		public SrvRecord(int priority, int weight, int port, String target) {
			Validate.inclusiveBetween(0, 0xFFFF, priority, "priority must be between 0 and 65535");
			Validate.inclusiveBetween(0, 0xFFFF, weight, "weight must be between 0 and 65535");
			Validate.inclusiveBetween(0, 0xFFFF, port, "port must be between 0 and 65535");
			Validate.notEmpty(target, "target cannot be null or empty");

			this.priority = priority;
			this.weight = weight;
			this.port = port;
			this.target = target;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null || !(obj instanceof SrvRecord))
				return false;

			SrvRecord that = (SrvRecord) obj;

			return priority == that.priority && weight == that.weight && port == that.port
					&& target.equals(that.target);
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder("SRV RR: ");
			builder.append(priority).append(' ');
			builder.append(weight).append(" (").append(sum).append(") ");
			builder.append(port).append(' ');
			builder.append(target).append(' ');
			return builder.toString();
		}

		@Override
		public int compareTo(SrvRecord that) {
			// Comparing according to the RFC
			if (priority > that.priority) {
				return 1;
			} else if (priority < that.priority) {
				return -1;
			} else if (weight == 0 && that.weight != 0) {
				return -1;
			} else if (weight != 0 && that.weight == 0) {
				return 1;
			} else {
				return 0;
			}
		}

	}

	/**
	 * A mere container for a server and along a service port.
	 */
	public static class HostPort {

		private String host;
		private int port;

		public HostPort(String host, int port) {
			Validate.notEmpty(host, "host cannot be null or empty");
			Validate.inclusiveBetween(0, 0xFFFF, port, "port must be between 0 and 65535");

			this.host = host;
			this.port = port;
		}

		public String getHost() {
			return host;
		}

		public int getPort() {
			return port;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null || !(obj instanceof HostPort))
				return false;

			HostPort that = (HostPort) obj;

			return host.equals(that.host) && port == that.port;
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append(host).append(':').append(port);
			return builder.toString();
		}

	}

	private static final String SRV_RR_FORMAT = "_%s._tcp.%s";
	private static final String SRV_RR_WITH_SITES_FORMAT = "_%s._tcp.%s._sites.%s";

	private static final String SRV_RR = "SRV";
	private static final String[] SRV_RR_ATTR = new String[] { SRV_RR };

	private static final Logger logger = Logger
			.getLogger(ActiveDirectoryServiceLocator.class.getName());

	private final Hashtable<String, Object> env;
	private final int maxBackupServers;

	Random random = new Random();

	private ActiveDirectoryServiceLocator(Builder builder) {
		env = new Hashtable<String, Object>();
		maxBackupServers = builder.maxBackupServers;
		env.put(Context.INITIAL_CONTEXT_FACTORY, builder.contextFactory);
		env.putAll(builder.additionalProperties);
	}

	/**
	 * A builder to construct an {@link ActiveDirectoryServiceLocator} with a fluent interface.
	 *
	 * <p>
	 * <strong>Notes:</strong>
	 * <ol>
	 * <li>This class is not thread-safe. Configure the builder in your main thread, build the
	 * object and pass it on to your forked threads.</li>
	 * <li>An {@code IllegalStateException} is thrown if a property is modified after this builder
	 * has already been used to build an {@code ActiveDirectoryServiceLocator}, simply create a new
	 * builder in this case.</li>
	 * <li>All passed arrays will be defensively copied and null/empty values will be skipped except
	 * when all elements are invalid, an exception will be raised.</li>
	 * </ol>
	 */
	public static final class Builder {

		// Builder properties
		private String contextFactory;
		private int maxBackupServers;
		private Hashtable<String, Object> additionalProperties;

		private boolean done;

		/**
		 * Constructs a new builder for {@link ActiveDirectoryServiceLocator}.
		 */
		public Builder() {
			// Initialize default values first as mentioned in the class' Javadoc
			contextFactory("com.sun.jndi.dns.DnsContextFactory");
			maxBackupServers(1);
			additionalProperties = new Hashtable<String, Object>();
		}

		/**
		 * Sets the context factory for this service locator.
		 *
		 * @param contextFactory
		 *            the context factory class name
		 * @throws NullPointerException
		 *             if {@code contextFactory} is null
		 * @throws IllegalArgumentException
		 *             if {@code contextFactory} is empty
		 * @return this builder
		 */
		public Builder contextFactory(String contextFactory) {
			check();
			this.contextFactory = validateAndReturnString("contextFactory", contextFactory);
			return this;
		}

		/**
		 * Sets the maximum amount of backup servers. The total amount of servers returned is always
		 * {@code maxBackupServers} + 1 unless the DNS server returns less resource records.
		 *
		 * @param maxBackupServers
		 *            The maximum amount of backup servers. This value must be a positive integer.
		 * @throws IllegalArgumentException
		 *             if {@code maxBackupServers} is not a positive integer
		 * @return this builder
		 */
		public Builder maxBackupServers(int maxBackupServers) {
			check();
			Validate.isTrue(maxBackupServers > 0,
					"Property 'maxBackupServers' must be greater than zero but is %d",
					maxBackupServers);
			this.maxBackupServers = maxBackupServers;
			return this;
		}

		/**
		 * Sets an additional property not available through the builder interface.
		 *
		 * @param name
		 *            name of the property
		 * @param value
		 *            value of the property
		 * @throws NullPointerException
		 *             if {@code name} is null
		 * @throws IllegalArgumentException
		 *             if {@code value} is empty
		 * @return this builder
		 */
		public Builder additionalProperty(String name, Object value) {
			check();
			Validate.notEmpty(name, "Additional property's name cannot be null or empty");
			this.additionalProperties.put(name, value);
			return this;
		}

		/**
		 * Builds an {@code ActiveDirectoryServiceLocator} and marks this builder as non-modifiable
		 * for future use. You may call this method as often as you like, it will return a new
		 * {@code ActiveDirectoryServiceLocator} instance on every call.
		 *
		 * @throws IllegalStateException
		 *             if a combination of necessary attributes is not set
		 * @return an {@code ActiveDirectoryServiceLocator} object
		 */
		public ActiveDirectoryServiceLocator build() {

			ActiveDirectoryServiceLocator serviceLocator = new ActiveDirectoryServiceLocator(this);
			done = true;

			return serviceLocator;
		}

		private void check() {
			if (done)
				throw new IllegalStateException("Cannot modify an already used builder");
		}

		private String validateAndReturnString(String name, String value) {
			return Validate.notEmpty(value, "Property '%s' cannot be null or empty", name);
		}

	}

	private SrvRecord[] lookUpSrvRecords(DirContext context, String name) throws NamingException {
		Attributes attrs = null;

		try {
			attrs = context.getAttributes(name, SRV_RR_ATTR);
		} catch (InvalidNameException e) {
			throw new IllegalArgumentException("name '" + name + "' is invalid", e);
		} catch (NameNotFoundException e) {
			return null;
		}

		Attribute srvAttr = attrs.get(SRV_RR);
		if (srvAttr == null)
			return null;

		NamingEnumeration<?> records = null;

		SrvRecord[] srvRecords = new SrvRecord[srvAttr.size()];

		try {
			records = srvAttr.getAll();

			int recordCnt = 0;
			while (records.hasMoreElements()) {
				String record = (String) records.nextElement();
				Scanner scanner = new Scanner(record);
				scanner.useDelimiter(" ");

				int priority = scanner.nextInt();
				int weight = scanner.nextInt();
				int port = scanner.nextInt();
				String target = scanner.next();
				SrvRecord srvRecord = new SrvRecord(priority, weight, port, target);

				srvRecords[recordCnt++] = srvRecord;
				scanner.close();
			}
		} finally {
			if (records != null)
				try {
					records.close();
				} catch (NamingException e) {
					; // ignore
				}
		}

		/*
		 * No servers returned or explicit indication by the DNS server that this service is not
		 * provided as described by the RFC.
		 */
		if (srvRecords.length == 0 || srvRecords.length == 1
				&& srvRecords[0].target.equals(SrvRecord.UNVAILABLE_SERVICE))
			return null;

		return srvRecords;
	}

	private HostPort[] sortByRfc2782(SrvRecord[] srvRecords) {
		if (srvRecords == null)
			return null;

		// Apply the server selection algorithm
		Arrays.sort(srvRecords);
		System.out.println(srvRecords.length + ": " + Arrays.toString(srvRecords));

		HostPort[] sortedServers = new HostPort[srvRecords.length];
		for (int i = 0, start = -1, end = -1, hp = 0; i < srvRecords.length; i++) {

			start = i;
			while (i + 1 < srvRecords.length
					&& srvRecords[i].priority == srvRecords[i + 1].priority) {
				i++;
			}
			end = i;

			// TODO Log priority groups
			System.out.printf("Start: %d, End: %d%n", start, end);

			for (int repeat = 0; repeat < (end - start) + 1; repeat++) {
				int sum = 0;
				for (int j = start; j <= end; j++) {
					if (srvRecords[j] != null) {
						sum += srvRecords[j].weight;
						srvRecords[j].sum = sum;
					}
				}

				int r = sum == 0 ? 0 : random.nextInt(sum + 1);
				for (int k = start; k <= end; k++) {
					SrvRecord srvRecord = srvRecords[k];

					if (srvRecord != null && srvRecord.sum >= r) {
						sortedServers[hp++] = new HostPort(StringUtils.chop(srvRecord.target),
								srvRecord.port);
						srvRecords[k] = null;
					}
				}
			}
		}

		// TODO Log sortedServers

		return sortedServers;
	}

	/**
	 * Locates a desired service within an Active Directory site and domain, sorted and selected
	 * according to RFC 2782.
	 *
	 * @param service
	 *            the service to be located
	 * @param site
	 *            the Active Directory site the client resides in
	 * @param domain
	 *            the desired domain. Can be any naming context name.
	 * @return the located servers or null of none found
	 * @throws NullPointerException
	 *             if service or domain is null
	 * @throws IllegalArgumentException
	 *             if service or domain is empty
	 * @throws RuntimeException
	 *             if an error has occured while creating the DNS directory context
	 * @throws IllegalArgumentException
	 *             if any of the provided arguments does not adhere to the RFC
	 */
	public HostPort[] locate(String service, String site, String domain) {
		Validate.notEmpty(service, "service cannot be null or empty");
		Validate.notEmpty(domain, "domain cannot be null or empty");

		DirContext context = null;
		try {
			context = new InitialDirContext(env);
		} catch (NamingException e) {
			throw new RuntimeException("Failed to create DirContext for DNS lookups", e);
		}

		SrvRecord[] srvRecords = null;

		String lookupName;
		if (StringUtils.isNotEmpty(site))
			lookupName = String.format(SRV_RR_WITH_SITES_FORMAT, service, site, domain);
		else
			lookupName = String.format(SRV_RR_FORMAT, service, domain);

		// TODO Log lookupName
		try {
			srvRecords = lookUpSrvRecords(context, lookupName);
		} catch (NamingException e) {
			// TODO Log this
			return null;
		} finally {
			try {
				context.close();
			} catch (NamingException e) {
				; // ignore
			}
		}

		// TODO Log srvRecords
		HostPort[] servers = sortByRfc2782(srvRecords);

		// We have more servers than requested, cut off
		if (servers != null && servers.length > maxBackupServers + 1)
			return Arrays.copyOfRange(servers, 0, maxBackupServers + 1);

		// Log servers

		return servers;
	}

	/**
	 * Locates a desired service within an Active Directory domain, sorted and selected
	 * according to RFC 2782.
	 *
	 * @param service
	 *            the service to be located
	 * @param domain
	 *            the desired domain. Can be any naming context name.
	 * @return the located servers or null of none found
	 * @throws NullPointerException
	 *             if service or domain is null
	 * @throws IllegalArgumentException
	 *             if service or domain is empty
	 * @throws RuntimeException
	 *             if an error has occured while creating the DNS directory context
	 * @throws IllegalArgumentException
	 *             if any of the provided arguments does not adhere to the RFC
	 */
	public HostPort[] locate(String service, String domain) {
		return locate(service, null, domain);
	}

}
