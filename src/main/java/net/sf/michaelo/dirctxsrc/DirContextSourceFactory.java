/*
 * Copyright 2013–2025 Michael Osipov
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

import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.RefAddr;
import javax.naming.Reference;
import javax.naming.spi.ObjectFactory;

import org.apache.commons.lang3.StringUtils;

/**
 * An object factory for creating {@link DirContextSource} instances backed by a
 * {@link DirContextSource.Builder}.
 *
 * This factory should work in any servlet container with JNDI support, but was tested under Apache
 * Tomcat 8.5.x only.
 * <p>
 * Integration in your {@code context.xml} is as simple as:
 *
 * <pre>
 * &lt;Context&gt;
 * [...]
 *   &lt;!-- Add this --&gt;
 *   &lt;Resource name="ldap/localname" type="net.sf.michaelo.dirctxsrc.DirContextSource"
 *     factory="net.sf.michaelo.dirctxsrc.DirContextSourceFactory"
 *     urls="ldap://hostname ldap://another-hostname" /&gt;
 * [...]
 * &lt;/Context&gt;
 * </pre>
 *
 * For a complete reference, see
 * <a href="https://michael-o.github.io/dirctxsrc/dircontextsourcefactory.html">documentation site</a>.
 */
public class DirContextSourceFactory implements ObjectFactory {

	protected static final String PROP_CONTEXT_FACTORY = "contextFactory";
	protected static final String PROP_URLS = "urls";
	protected static final String PROP_AUTH = "auth";
	protected static final String PROP_LOGIN_ENTRY_NAME = "loginEntryName";
	protected static final String PROP_OBJECT_FACTORIES = "objectFactories";
	protected static final String PROP_MUTUAL_AUTH = "mutualAuth";
	protected static final String PROP_QOP = "qop";
	protected static final String PROP_DEBUG = "debug";
	protected static final String PROP_RETRIES = "retries";
	protected static final String PROP_RETRY_WAIT = "retryWait";
	protected static final String PROP_BINARY_ATTRIBUTES = "binaryAttributes";
	protected static final String PROP_REFERRAL = "referral";
	protected static final String PROP_DEREF_ALIASES = "derefAliases";
	protected static final String PROP_VERSION = "version";
	protected static final String PROP_CONNECT_TIMEOUT = "connectTimeout";
	protected static final String PROP_ADDITIONAL_PROPERTIES = "additionalProperties";

	protected static final List<String> PROPERTIES_NAMES = Collections
			.unmodifiableList(Arrays.asList(PROP_CONTEXT_FACTORY, PROP_URLS, PROP_AUTH,
					PROP_LOGIN_ENTRY_NAME, PROP_OBJECT_FACTORIES, PROP_MUTUAL_AUTH, PROP_QOP,
					PROP_DEBUG, PROP_RETRIES, PROP_RETRY_WAIT, PROP_BINARY_ATTRIBUTES,
					PROP_REFERRAL, PROP_DEREF_ALIASES, PROP_VERSION, PROP_CONNECT_TIMEOUT,
					PROP_ADDITIONAL_PROPERTIES));

	protected final Properties properties = new Properties();

	@Override
	public Object getObjectInstance(Object obj, Name name, Context ctx, Hashtable<?, ?> environment)
			throws Exception {

		if (obj == null || !(obj instanceof Reference))
			return null;

		Reference ref = (Reference) obj;
		if (!ref.getClassName().equals(DirContextSource.class.getName()))
			return null;

		for (String propertyName : PROPERTIES_NAMES) {
			RefAddr ra = ref.get(propertyName);
			if (ra != null) {
				String propertyValue = ra.getContent().toString();
				properties.setProperty(propertyName, propertyValue);
			}
		}

		String str = getProperty(PROP_URLS);
		DirContextSource.Builder builder = new DirContextSource.Builder(StringUtils.split(str));

		str = getProperty(PROP_CONTEXT_FACTORY);
		if (StringUtils.isNotEmpty(str))
			builder.contextFactory(str);

		str = getProperty(PROP_AUTH);
		if (StringUtils.isNotEmpty(str))
			builder.auth(DirContextSource.Auth.valueOf(str.toUpperCase(Locale.ENGLISH)));

		str = getProperty(PROP_LOGIN_ENTRY_NAME);
		if (StringUtils.isNotEmpty(str))
			builder.loginEntryName(str);

		str = getProperty(PROP_MUTUAL_AUTH);
		builder.mutualAuth(Boolean.parseBoolean(str));

		str = getProperty(PROP_QOP);
		if (StringUtils.isNotEmpty(str))
			builder.qop(StringUtils.split(str));

		str = getProperty(PROP_DEBUG);
		builder.debug(Boolean.parseBoolean(str));

		str = getProperty(PROP_RETRIES);
		if (StringUtils.isNotEmpty(str))
			builder.retries(parseInt(PROP_RETRIES, str));

		str = getProperty(PROP_RETRY_WAIT);
		if (StringUtils.isNotEmpty(str))
			builder.retryWait(parseInt(PROP_RETRY_WAIT, str));

		str = getProperty(PROP_BINARY_ATTRIBUTES);
		if (StringUtils.isNotEmpty(str))
			builder.binaryAttributes(StringUtils.split(str));

		str = getProperty(PROP_REFERRAL);
		if (StringUtils.isNotEmpty(str))
			builder.referral(str);

		str = getProperty(PROP_DEREF_ALIASES);
		if (StringUtils.isNotEmpty(str))
			builder.derefAliases(str);

		str = getProperty(PROP_VERSION);
		if (StringUtils.isNotEmpty(str))
			builder.version(parseInt(PROP_VERSION, str));

		str = getProperty(PROP_CONNECT_TIMEOUT);
		if (StringUtils.isNotEmpty(str))
			builder.connectTimeout(parseInt(PROP_CONNECT_TIMEOUT, str));

		str = getProperty(PROP_ADDITIONAL_PROPERTIES);
		if (StringUtils.isNotEmpty(str)) {
			String[] additionalProperties = StringUtils.split(str, ';');
			String[] splittedAdditionalProperty;
			for (String additionalProperty : additionalProperties) {
				splittedAdditionalProperty = StringUtils.split(additionalProperty, "=");
				builder.additionalProperty(splittedAdditionalProperty[0],
						splittedAdditionalProperty[1]);
			}
		}

		return builder.build();
	}

	protected String getProperty(String propertyName) {
		return properties.getProperty(propertyName);
	}

	protected int parseInt(String name, String value) {
		try {
			return Integer.parseInt(value);
		} catch (NumberFormatException e) {
			throw new IllegalArgumentException(String.format("Property '%s' must be an integer", name));
		}
	}

}
