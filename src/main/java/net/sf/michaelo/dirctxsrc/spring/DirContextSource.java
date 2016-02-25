package net.sf.michaelo.dirctxsrc.spring;

import java.util.Map;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;

import net.sf.michaelo.dirctxsrc.DirContextSource.Auth;
import net.sf.michaelo.dirctxsrc.DirContextSource.Builder;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.ldap.core.ContextSource;

public class DirContextSource implements ContextSource, InitializingBean {

	private net.sf.michaelo.dirctxsrc.DirContextSource.Builder builder;
	private net.sf.michaelo.dirctxsrc.DirContextSource contextSource;

	/**
	 * A Spring LDAP {@link ContextSource} wrapper for
	 * {@link net.sf.michaelo.dirctxsrc.DirContextSource DirContextSource}.
	 *
	 * <p>
	 * A minimal example how to create a {@code DirContextSource} with the supplied builder:
	 *
	 * <pre>
	 * &lt;beans:bean class=&quot;net.sf.michaelo.dirctxsrc.spring.DirContextSource&quot;&gt;
	 *  &lt;beans:constructor-arg&gt;
	 *    &lt;beans:array&gt;
	 *      &lt;beans:value&gt;ldap://hostname&lt;/beans:value&gt;
	 *    &lt;/beans:array&gt;
	 *  &lt;/beans:constructor-arg&gt;
	 * &lt;/beans:bean&gt;
	 * </pre>
	 *
	 * </p>
	 *
	 * <p>
	 * A {@code DirContextSource} object will be initially preconfigured by its builder for you:
	 * <ol>
	 * <li>The object factory is set by default to
	 * <code>org.springframework.ldap.core.support.DefaultDirObjectFactory</code>.</li>
	 * </ol>
	 * </p>
	 *
	 * @see net.sf.michaelo.dirctxsrc.DirContextSource
	 */
	public DirContextSource(String... urls) {
		builder = new net.sf.michaelo.dirctxsrc.DirContextSource.Builder(urls);
		builder.objectFactories("org.springframework.ldap.core.support.DefaultDirObjectFactory");
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		contextSource = builder.build();
	}

	@Override
	public DirContext getReadOnlyContext() {
		try {
			return contextSource.getDirContext();
		} catch (NamingException e) {
			throw org.springframework.ldap.support.LdapUtils.convertLdapException(e);
		}
	}

	@Override
	public DirContext getReadWriteContext() {
		try {
			return contextSource.getDirContext();
		} catch (NamingException e) {
			throw org.springframework.ldap.support.LdapUtils.convertLdapException(e);
		}
	}

	@Override
	public DirContext getContext(String principal, String credentials) {
		throw new UnsupportedOperationException(
				"A context can only be created explicitly with a login config name");
	}

	/**
	 * @see Builder#contextFactory(String)
	 */
	public void setContextFactory(String contextFactory) {
		builder.contextFactory(contextFactory);
	}

	/**
	 * @see Builder#auth(Auth)
	 */
	public void setAuth(Auth auth) {
		builder.auth(auth);
	}

	/**
	 * @see Builder#loginEntryName(String)
	 */
	public void setLoginEntryName(String loginEntryName) {
		builder.loginEntryName(loginEntryName);
	}

	/**
	 * @see Builder#debug(boolean)
	 */
	public void setDebug(boolean debug) {
		builder.debug(debug);
	}

	/**
	 * @see Builder#qop(String...)
	 */
	public void setQop(String... qop) {
		builder.qop(qop);
	}

	/**
	 * @see Builder#mutualAuth(boolean)
	 */
	public void setMutualAuth(boolean mutualAuth) {
		builder.mutualAuth(mutualAuth);
	}

	/**
	 * @see Builder#retries(int)
	 */
	public void setRetries(int retries) {
		builder.retries(retries);
	}

	/**
	 * @see Builder#retryWait(int)
	 */
	public void setRetryWait(int retryWait) {
		builder.retryWait(retryWait);
	}

	/**
	 * @see Builder#binaryAttributes(String...)
	 */
	public void setBinaryAttributes(String... binaryAttributes) {
		builder.binaryAttributes(binaryAttributes);
	}

	/**
	 * @see Builder#additionalProperty(String, Object)
	 */
	public void setAdditionalProperties(Map<String, Object> additionalProperties) {
		for (Map.Entry<String, Object> additionalProperty : additionalProperties.entrySet())
			builder.additionalProperty(additionalProperty.getKey(), additionalProperty.getValue());
	}

}
