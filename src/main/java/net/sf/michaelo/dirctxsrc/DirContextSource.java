/*
 * Copyright 2012 Michael Osipov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.sf.michaelo.dirctxsrc;

import java.io.OutputStream;
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

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;

/**
 * A JNDI directory context factory returning ready-to-use {@link DirContext}
 * objects. The basic idea is borrowed from {@link javax.sql.DataSource} where
 * you get a database connection. Same does this class with directory contexts.
 *
 * <p>
 * This directory context source has built-in support for anonymous and GSS-API
 * with Kerberos 5 authentication.<br />
 * <em>Note:</em> Make sure that your environment is well configured if you
 * intend to use GSS-API with Kerberos 5.
 * </p>
 *
 * A minimal example how to create a {@code DirContextSource} with the supplied
 * builder:
 *
 * <pre>
 * DirContextSource.Builder builder = new DirContextSource.Builder(&quot;ldap://hostname&quot;);
 * DirContextSource contextSource = builder.build();
 * DirContext context = contextSource.getDirContext();
 * // Perform operations
 * context.close();
 * </pre>
 *
 * <p>
 * Before returning a {@code DirContext} the source will loop several times
 * until a connection has been established or the number of retries are
 * exhausted, which ever comes first. <br />
 * A {@code DirContextSource} object will be initially preconfigured by its
 * builder for you:
 * <ol>
 * <li>The context factory is set by default to
 * <code>com.sun.jndi.ldap.LdapCtxFactory</code>.</li>
 * <li>The default authentication scheme is set to none/anonymous.</li>
 * <li>If GSS-API authentication is used the login entry name defaults to
 * {@code DirContextSource}.</li>
 * <li>By default a context source will retry up to three times to connect and
 * will wait for 2000 ms between retries.</li>
 * </ol>
 * </p>
 *
 * A complete overview of all {@code DirContext} properties can be found <a
 * href= "http://docs.oracle.com/javase/1.5.0/docs/guide/jndi/jndi-ldap-gl.html"
 * >here</a>. Make sure that you pass reasonable/valid values only otherwise
 * runtime behavior is undefined.
 *
 * @version $Id$
 */
public class DirContextSource {

	/**
	 * Enum containing all supported authentication mechanisms.
	 */
	public static enum Auth {

		NONE("none"),
		GSSAPI("GSSAPI");

		private String securityAuthName;

		Auth(String securityAuthName) {
			this.securityAuthName = securityAuthName;
		}

		String getSecurityAuthName() {
			return securityAuthName;
		}
	}

	private static final Logger logger = Logger
			.getLogger(DirContextSource.class.getName());
	private final Hashtable<String, Object> env;
	private final String loginEntryName;
	private final int retries;
	private final int retryWait;
	private final Auth auth;

	private DirContextSource(Builder builder) {
		env = new Hashtable<String, Object>();

		env.put(Context.INITIAL_CONTEXT_FACTORY, builder.contextFactory);
		env.put(Context.PROVIDER_URL, StringUtils.join(builder.urls, ' '));
		env.put(Context.SECURITY_AUTHENTICATION, builder.auth.getSecurityAuthName());
		auth = builder.auth;
		loginEntryName = builder.loginEntryName;
		if(builder.objectFactories != null)
			env.put(Context.OBJECT_FACTORIES, StringUtils.join(builder.objectFactories, ':'));
		env.put("javax.security.sasl.server.authentication", Boolean.toString(builder.mutualAuth));
		if(builder.qops != null)
			env.put("javax.security.sasl.qop", StringUtils.join(builder.qops, ','));
		if(builder.debug)
			env.put("com.sun.jndi.ldap.trace.ber", builder.debugStream);
		retries = builder.retries;
		retryWait = builder.retryWait;
		if(builder.binaryAttributes != null)
			env.put("java.naming.ldap.attributes.binary", StringUtils.join(builder.binaryAttributes, ' '));
		env.putAll(builder.additionalProperties);
	}

	/**
	 * A builder to construct a {@link DirContextSource} with a fluent
	 * interface.
	 *
	 * <p>
	 * <em>Note</em>: This class is not thread-safe. Configure the builder
	 * in your main thread, build the object and pass it on to your forked threads.
	 * <br />
	 * <em>Note</em>: An {@code IllegalStateException} is thrown if a property
	 * is modified and this builder has already been used to build a
	 * {@code DirContextSource}, simply create a new builder.
	 * </p>
	 */
	public static final class Builder {

		// Builder properties
		private String contextFactory;
		private String[] urls;
		private Auth auth;
		private String loginEntryName;
		private String[] objectFactories;
		private boolean mutualAuth;
		private String[] qops;
		private boolean debug;
		private OutputStream debugStream;
		private int retries;
		private int retryWait;
		private String[] binaryAttributes;
		private Hashtable<String, Object> additionalProperties;

		private boolean done;

		/**
		 * Constructs a new builder for {@link DirContextSource} with anonymous
		 * authentication.
		 *
		 * @param urls
		 *            The URLs of directory servers. They may contain root DNs.
		 *            The connection routine iterates through all URLs/servers
		 *            until one is reachable.
		 * @throws NullPointerException
		 *             if {@code urls} is null
		 * @throws IllegalArgumentException
		 *             if {@code urls} is empty
		 */
		public Builder(String... urls) {
			// Initialize default values first as mentioned in the class' JavaDoc
			contextFactory("com.sun.jndi.ldap.LdapCtxFactory");
			auth(Auth.NONE);
			loginEntryName("DirContextSource");
			retries(3);
			retryWait(2000);
			additionalProperties = new Hashtable<String, Object>();

			urls(urls);
		}

		/**
		 * Sets the context factory for this directory context.
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
			Validate.notEmpty(contextFactory,
					"Property 'contextFactory' cannot be null or empty");
			this.contextFactory = contextFactory;
			return this;
		}

		private Builder urls(String... urls) {
			check();
			Validate.notEmpty(urls, "Property 'urls' cannot be null or empty");
			this.urls = urls;
			return this;
		}

		/**
		 * Sets the authentication scheme.
		 *
		 * @param auth
		 *            the auth to be used
		 * @throws NullPointerException
		 *             if {@code auth} is null
		 * @return this builder
		 */
		public Builder auth(Auth auth) {
			check();
			Validate.notNull(auth, "Property 'auth' cannot be null");
			this.auth = auth;
			return this;
		}

		/**
		 * Sets the login entry name for GSS-API authentication.
		 *
		 * @param loginEntryName
		 *            the login entry name which retrieves the GSS-API
		 *            credential
		 * @throws NullPointerException
		 *             if {@code loginEntryName} is null
		 * @throws IllegalArgumentException
		 *             if {@code loginEntryName} is empty
		 * @return this builder
		 */
		public Builder loginEntryName(String loginEntryName) {
			check();
			Validate.notEmpty(loginEntryName,
					"Property 'loginEntryName' cannot be null or empty");
			this.loginEntryName = loginEntryName;
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
		 * @throws NullPointerException
		 *             if {@code loginEntryName} is null
		 * @throws IllegalArgumentException
		 *             if {@code loginEntryName} is empty
		 * @see #loginEntryName(String)
		 * @return this builder
		 */

		public Builder gssApiAuth(String loginEntryName) {
			return auth(Auth.GSSAPI).loginEntryName(loginEntryName);
		}

		/**
		 * Sets the object factories for this directory context.
		 *
		 * @param objectFactories
		 *            the objectFactories class names
		 * @throws NullPointerException
		 *             if {@code objectFactories} is null
		 * @throws IllegalArgumentException
		 *             if {@code objectFactories} is empty
		 * @return this builder
		 */
		public Builder objectFactories(String... objectFactories) {
			check();
			Validate.notEmpty(objectFactories,
					"Property 'objectFactories' cannot be null or empty");
			this.objectFactories = objectFactories;
			return this;
		}

		/**
		 * Enables the mutual authentication between client and directory
		 * server. This only works with SASL mechanisms which support this
		 * feature, e.g., GSS-API.
		 *
		 * @return this builder
		 */
		public Builder mutualAuth() {
			return mutualAuth(true);
		}

		/**
		 * Enables or disables the mutual authentication between client and
		 * directory server. This only works with SASL mechanisms which support
		 * this feature, e.g., GSS-API.
		 *
		 * @param mutualAuth
		 *            the mutual authentication flag
		 * @return this builder
		 */
		public Builder mutualAuth(boolean mutualAuth) {
			check();
			this.mutualAuth = mutualAuth;
			return this;
		}

		/**
		 * Sets the quality of protection(s) with which the connection to the
		 * directory server is secured. Valid values are {@code auth},
		 * {@code auth-int}, and {@code auth-conf}. This only works with SASL
		 * mechanisms which support this feature, e.g., Digest MD5 or GSS-API.
		 * See <a href=
		 * "http://docs.oracle.com/javase/jndi/tutorial/ldap/security/sasl.html#qop"
		 * >here</a> for details.
		 *
		 * @param qops
		 *            the quality of protection(s) for this dir context
		 *            connection
		 * @throws NullPointerException
		 *             if {@code qops} is null
		 * @throws IllegalArgumentException
		 *             if {@code qops} is empty
		 * @return this builder
		 */
		public Builder qops(String... qops) {
			check();
			Validate.notEmpty(qops, "Property 'urls' cannot be null or empty");
			this.qops = qops;
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
		 *            the debug flag
		 * @return this builder
		 */
		public Builder debug(boolean debug) {
			check();
			this.debug = debug;
			this.debugStream = debug ? System.err : null;
			return this;
		}

		/**
		 * Redirects the LDAP debug output to a {@link OutputStream}.
		 *
		 * @param stream
		 *            an {@code OutputStream} where debug output will be written to
		 * @throws NullPointerException
		 *             if {@code stream} is null
		 * @return this builder
		 */
		public Builder debug(OutputStream stream) {
			check();
			Validate.notNull(stream, "Property 'stream' cannot be null");
			debug();
			this.debugStream = stream;
			return this;
		}

		/**
		 * Sets the number or connection retries.
		 *
		 * @param retries
		 *            The number of retries. This value must be a positive
		 *            integer.
		 * @throws IllegalArgumentException
		 *             if {@code retries} is not a positive integer
		 * @return this builder
		 */
		public Builder retries(int retries) {
			check();
			Validate.isTrue(retries > 0,
					"Property 'retries' must be greater than zero but is %d",
					retries);
			this.retries = retries;
			return this;
		}

		/**
		 * Sets the wait interval between reconnections.
		 *
		 * @param retryWait
		 *            The wait time in milliseconds. This value must be a
		 *            positive integer.
		 * @throws IllegalArgumentException
		 *             if {@code retryWait} is not a positive integer
		 * @return this builder
		 */
		public Builder retryWait(int retryWait) {
			check();
			Validate.isTrue(retryWait > 0,
					"Property 'retryWait' must be greater than zero but is %d",
					retryWait);
			this.retryWait = retryWait;
			return this;
		}

		/**
		 * Sets those attributes which will be returned as {@code byte[]}
		 * instead of {@code String}. See <a href=
		 * "http://docs.oracle.com/javase/1.5.0/docs/guide/jndi/jndi-ldap-gl.html#LDAPPROPS"
		 * >here</a> for details.
		 *
		 * @param attributes
		 *            the attributes to be returned as byte array
		 * @throws NullPointerException
		 *             if {@code attributes} is null
		 * @throws IllegalArgumentException
		 *             if {@code attributes} is empty
		 * @return this builder
		 */
		public Builder binaryAttributes(String... attributes) {
			check();
			Validate.notEmpty(attributes,
					"Property 'attributes' cannot be null or empty");
			this.binaryAttributes = attributes;
			return this;
		}

		/**
		 * Sets an additional property not available through the builder
		 * interface.
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
			Validate.notEmpty(name,
					"Additional property's name cannot be null or empty");
			this.additionalProperties.put(name, value);
			return this;
		}

		/**
		 * Builds a {@code DirContextSource} and marks this builder as
		 * non-modifiable for future use. You may call this method as often as
		 * you like, it will return a new {@code DirContextSource} instance
		 * on every call.
		 *
		 * @return a {@code DirContextSource} object
		 */
		public DirContextSource build() {
			DirContextSource contextSource = new DirContextSource(this);
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
	 * @throws javax.naming.NamingException
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
