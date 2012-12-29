package net.sf.michaelo.dirctxsrc;

import java.io.PrintWriter;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Hashtable;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.commons.lang.StringUtils;

/**
 * A handy utility to create a {@link DirContext} with a fluent interface. It
 * has built-in support for anonymous and GSS-API with Kerberos 5
 * authentication. <br />
 * <em>Note:</em> Make sure that your environment is well configured if you
 * intend to use GSS-API with Kerberos 5.
 * <p>
 * A minimal example how to create a {@code DirContextSource}:
 * 
 * <pre>
 * DirContextSource.Builder builder = new DirContextSource.Builder(&quot;ldap://servername&quot;);
 * DirContextSource contextSource = builder.build();
 * DirContext context = contextSource.getDirContext();
 * // Perform operations
 * context.close();
 * </pre>
 * 
 * </p>
 * 
 * <p>
 * Before returning a {@code DirContext} the source will loop several times
 * until a connection has been established or the number of retries are
 * exhausted, which ever comes first. <br />
 * The {@code DirContextSource} has been conveniently preconfigured for you:
 * <ol>
 * <li>The context factory is set by default to
 * <code>com.sun.jndi.ldap.LdapCtxFactory</code>.</li>
 * <li>The default authentication scheme is set to none/anonymous.</li>
 * <li>If GSS-API authentication is used the login entry name defaults to
 * {@code DirContextSource}.</li>
 * <li>By default the source will retry up to three times to connect and will
 * wait for 2000 ms between retries.</li>
 * </ol>
 * </p>
 * 
 * A complete overview of all {@code DirContext} properties can be found <a
 * href= "http://docs.oracle.com/javase/1.5.0/docs/guide/jndi/jndi-ldap-gl.html"
 * >here</a>.
 * 
 * @version $Id$
 */
public class DirContextSource {

	public static enum Auth {

		NONE {
			@Override
			String getSecurityAuthName() {
				return "none";
			}
		},
		GSSAPI {
			@Override
			String getSecurityAuthName() {
				return "GSSAPI";
			}
		};

		abstract String getSecurityAuthName();
	}

	private static final Logger logger = Logger
			.getLogger(DirContextSource.class.getName());
	private final Hashtable<String, Object> env;
	private String loginEntryName = "DirContextSource";
	private int retries = 3;
	private int retryWait = 2000;
	private Auth auth;

	private DirContextSource() {
		env = new Hashtable<String, Object>();
		env.put(Context.INITIAL_CONTEXT_FACTORY,
				"com.sun.jndi.ldap.LdapCtxFactory");
	}

	/**
	 * A builder to construct a {@link DirContextSource}.
	 */
	public static final class Builder {

		private final DirContextSource contextSource = new DirContextSource();
		private boolean done;

		/**
		 * Constructs a new builder for {@link DirContextSource} with anonymous
		 * authentication.
		 * 
		 * @param url
		 *            The URL or URLs separated by spaces of the directory
		 *            server(s). It may contain a root DN.
		 */
		public Builder(String url) {
			auth(Auth.NONE);
			contextSource.env.put(Context.PROVIDER_URL, url);
		}

		/**
		 * Sets the authentication scheme.
		 * 
		 * @param auth
		 *            the auth to be used
		 * @return this builder
		 */
		public Builder auth(Auth auth) {
			check();
			contextSource.auth = auth;
			contextSource.env.put(Context.SECURITY_AUTHENTICATION,
					auth.getSecurityAuthName());
			return this;
		}

		/**
		 * Sets the login entry name for GSS-API authentication.
		 * 
		 * @param loginEntryName
		 *            the login entry name which retrieves the GSS-API
		 *            credential
		 * @return this builder
		 */
		public Builder loginEntryName(String loginEntryName) {
			check();
			contextSource.loginEntryName = loginEntryName;
			return this;
		}

		/**
		 * Enables anonymous authentication.
		 * 
		 * @return this builder
		 */
		public Builder anonymousAuth() {
			return auth(Auth.NONE);
		}

		/**
		 * Enables GSS-API authentication with a default login entry name.
		 * 
		 * @return this builder
		 */
		public Builder gssApiAuth() {
			return auth(Auth.GSSAPI);
		}

		/**
		 * Enables GSS-API authentication with a custom login entry name.
		 * 
		 * @param loginEntryName
		 *            the login entry name which retrieves the GSS-API
		 *            credential
		 * @see #loginEntryName(String)
		 * @return this builder
		 */

		public Builder gssApiAuth(String loginEntryName) {
			return auth(Auth.GSSAPI).loginEntryName(loginEntryName);
		}

		/**
		 * Sets the context factory for this directory context.
		 * 
		 * @param contextFactory
		 *            the context factory class name
		 * @return this builder
		 */
		public Builder contextFactory(String contextFactory) {
			check();
			contextSource.env.put(Context.INITIAL_CONTEXT_FACTORY,
					contextFactory);
			return this;
		}

		/**
		 * Sets the object factories for this directory context.
		 * 
		 * @param objectFactories
		 *            the objectFactories class name
		 * @return this builder
		 */
		public Builder objectFactories(String objectFactories) {
			check();
			contextSource.env.put(Context.OBJECT_FACTORIES, objectFactories);
			return this;
		}

		/**
		 * Enables the mutual authentication between client and directory
		 * server. This only works with SASL mechanisms which support this
		 * feature, e.g. GSS-API.
		 * 
		 * @return this builder
		 */
		public Builder mutualAuth() {
			return mutualAuth(true);
		}

		/**
		 * Enables or disables the mutual authentication between client and
		 * directory server. This only works with SASL mechanisms which support
		 * this feature, e.g. GSS-API.
		 * 
		 * @param mutualAuth
		 *            the mutual authentication indication
		 * @return this builder
		 */
		public Builder mutualAuth(boolean mutualAuth) {
			check();
			contextSource.env.put("javax.security.sasl.server.authentication",
					Boolean.toString(mutualAuth));
			return this;
		}

		/**
		 * Sets the quality of protection with which the connection to the
		 * directory server is secured. Valid values are {@code auth},
		 * {@code auth-int}, and {@code auth-conf}. This only works with SASL
		 * mechanisms which support this feature, e.g. Digest MD5 or GSS-API.
		 * See <a href=
		 * "http://docs.oracle.com/javase/jndi/tutorial/ldap/security/sasl.html#qop"
		 * >here</a> for details.
		 * 
		 * @param qop
		 *            The quality of protection of the connection. Multiple
		 *            values may be passed as a comma-separated list.
		 * @return this builder
		 */
		public Builder qop(String qop) {
			check();
			contextSource.env.put("javax.security.sasl.qop", qop);
			return this;
		}

		/**
		 * Enables the redirection of the LDAP debug output to
		 * {@code System.err}.
		 * 
		 * @see #debug(boolean)
		 * @return this builder
		 */
		public Builder debug() {
			return debug(true);
		}

		/**
		 * Enables or disables the redirection of the LDAP debug output to
		 * {@code System.err}.
		 * 
		 * @param debug
		 *            the debug indication
		 * @return this builder
		 */
		public Builder debug(boolean debug) {
			check();
			if (debug)
				contextSource.env
						.put("com.sun.jndi.ldap.trace.ber", System.err);
			else
				contextSource.env.remove("com.sun.jndi.ldap.trace.ber");
			return this;
		}

		/**
		 * Redirects the LDAP debug output to a {@link PrintWriter}.
		 * 
		 * @param writer
		 *            a print writer where debug output will be written to
		 * @return this builder
		 */
		public Builder debug(PrintWriter writer) {
			check();
			contextSource.env.put("com.sun.jndi.ldap.trace.ber", writer);
			return this;
		}

		/**
		 * Sets the number or connection retries.
		 * 
		 * @param retries
		 *            The number of retries. This value must be a positive
		 *            integer.
		 * @return this builder
		 */
		public Builder retries(int retries) {
			check();
			contextSource.retries = retries;
			return this;
		}

		/**
		 * Sets the wait interval between reconnections.
		 * 
		 * @param retryWait
		 *            The wait time in milliseconds. This value must be a
		 *            positive integer.
		 * @return this builder
		 */
		public Builder retryWait(int retryWait) {
			check();
			contextSource.retryWait = retryWait;
			return this;
		}

		/**
		 * Sets those attributes which will be returned as {@code byte[]}
		 * instead of {@code String}. See <a href=
		 * "http://docs.oracle.com/javase/1.5.0/docs/guide/jndi/jndi-ldap-gl.html#LDAPPROPS"
		 * >here</a> for details.
		 * 
		 * @param attributes
		 *            The attributes to be returned as byte array. Multiple
		 *            values may be passed as a space-separated list.
		 * @return this builder
		 */
		public Builder binaryAttributes(String attributes) {
			check();
			contextSource.env.put("java.naming.ldap.attributes.binary",
					attributes);
			return this;
		}

		/**
		 * Sets an additional property not available through the builder
		 * interface.
		 * 
		 * @param name
		 *            name of the property
		 * 
		 * @param value
		 *            value of the property
		 * @return this builder
		 */
		public Builder additionalProperty(String name, Object value) {
			check();
			contextSource.env.put(name, value);
			return this;
		}

		/**
		 * Builds a {@code DirContextSource} and marks this builder as
		 * non-modifiable for future use.
		 * <p>
		 * <em>Note</em>: Before returning a context source this method will
		 * check whether the necessary set of properties for an authentication
		 * scheme has been set and throw an {@code IllegalStateException} if
		 * something is missing.<br />
		 * Necessary properties:
		 * <ul>
		 * <li>Anonymous auth: The URL</li>
		 * <li>GSS-API auth: The URL and a login entry name</li>
		 * </ul>
		 * </p>
		 * 
		 * @throws IllegalStateException
		 *             thrown is necessary properties are not set
		 * @return a {@code DirContextSource} object
		 */
		public DirContextSource build() {
			if (StringUtils.isEmpty((String) contextSource.env
					.get(Context.PROVIDER_URL)))
				throw new IllegalStateException(
						"Builder incomplete: URL is empty");

			if (contextSource.auth == null)
				throw new IllegalStateException(
						"Builder incomplete: Auth scheme is not set");

			switch (contextSource.auth) {
			case GSSAPI:
				if (StringUtils.isEmpty(contextSource.loginEntryName))
					throw new IllegalStateException(
							"Builder incomplete: Login entry name is not set for auth scheme GSS-API");
				break;

			default:
				// Nothing to do
				break;
			}
			done = true;
			return contextSource;
		}

		private void check() {
			if (done)
				throw new IllegalStateException(
						"Cannot modify an already used builder");
		}

	}

	protected DirContext getGssApiDirContext() throws NamingException {

		DirContext context = null;

		try {

			LoginContext lc = new LoginContext(loginEntryName);
			lc.login();

			context = Subject.doAs(lc.getSubject(),
					new PrivilegedExceptionAction<DirContext>() {

						public DirContext run() throws NamingException {

							int r = retries;
							InitialDirContext idc = null;

							while (r-- > 0) {

								try {
									idc = new InitialDirContext(env);
									break;
								} catch (NamingException e) {
									if (r == 0)
										throw e;

									String msg = String
											.format("Connecting to '%s' failed (%s), remaining retries: %s",
													env.get(Context.PROVIDER_URL),
													e, r);
									logger.warning(msg);

									try {
										Thread.sleep(retryWait);
									} catch (InterruptedException e1) {
										throw new NamingException(e1
												.getMessage());
									}
								}

							}

							return idc;
						}
					});

			lc.logout();
		} catch (PrivilegedActionException e) {
			throw (NamingException) e.getException();
		} catch (LoginException e) {
			NamingException ne = new NamingException(e.getMessage());
			ne.initCause(e);
			throw ne;
		} catch (SecurityException e) {
			NamingException ne = new NamingException(e.getMessage());
			ne.initCause(e);
			throw ne;
		}

		return context;
	}

	protected DirContext getAnonymousDirContext() throws NamingException {

		DirContext context = null;

		int r = retries;

		while (r-- > 0) {

			try {
				context = new InitialDirContext(env);
				break;
			} catch (NamingException e) {
				if (r == 0)
					throw e;

				String msg = String
						.format("Connecting to '%s' failed (%s), remaining retries: %s",
								env.get(Context.PROVIDER_URL), e, r);
				logger.warning(msg);

				try {
					Thread.sleep(retryWait);
				} catch (InterruptedException e1) {
					throw new NamingException(e1.getMessage());
				}
			}

		}

		return context;
	}

	/**
	 * Returns a ready-to-use {@code DirContext}. Do not forget to close the
	 * context after all operations.
	 * 
	 * @return a {@code DirContext}
	 * @throws NamingException
	 *             thrown if a problem with the creation arises
	 */
	public DirContext getDirContext() throws NamingException {

		switch (auth) {
		case NONE:
			return getAnonymousDirContext();
		case GSSAPI:
			return getGssApiDirContext();
		default:
			throw new AssertionError(auth);
		}

	}

}
