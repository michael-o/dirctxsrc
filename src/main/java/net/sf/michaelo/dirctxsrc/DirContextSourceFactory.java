/*
 * Copyright 2013–2016 Michael Osipov
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

import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;

/**
 * An object factory for creating {@link DirContextSource} instances backed by a
 * {@link DirContextSource.Builder}.
 *
 * This factory should work in any servlet container which JNDI support but was tested under Apache
 * Tomcat 6.0.x only.
 *
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
 * For a complete reference, see <a
 * href="http://dirctxsrc.sourceforge.net/dircontextsourcefactory.html" >documentation site</a>.
 * </p>
 *
 * @since 0.10
 * @version $Id$
 *
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
	protected static final String PROP_ADDITIONAL_PROPERTIES = "additionalProperties";

	protected static final List<String> PROPERTIES_NAMES = Collections.unmodifiableList(Arrays
			.asList(PROP_CONTEXT_FACTORY, PROP_URLS, PROP_AUTH, PROP_LOGIN_ENTRY_NAME,
					PROP_OBJECT_FACTORIES, PROP_MUTUAL_AUTH, PROP_QOP, PROP_DEBUG, PROP_RETRIES,
					PROP_RETRY_WAIT, PROP_BINARY_ATTRIBUTES, PROP_ADDITIONAL_PROPERTIES));

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
		builder.mutualAuth(BooleanUtils.toBoolean(str));

		str = getProperty(PROP_QOP);
		if (StringUtils.isNotEmpty(str))
			builder.qop(StringUtils.split(str));

		str = getProperty(PROP_DEBUG);
		builder.debug(BooleanUtils.toBoolean(str));

		str = getProperty(PROP_RETRIES);
		if (StringUtils.isNotEmpty(str)) {
			if (NumberUtils.isNumber(str))
				builder.retries(NumberUtils.toInt(str));
			else
				throw new IllegalArgumentException("Property 'retries' must be a number");
		}

		str = getProperty(PROP_RETRY_WAIT);
		if (StringUtils.isNotEmpty(str)) {
			if (NumberUtils.isNumber(str))
				builder.retryWait(NumberUtils.toInt(str));
			else
				throw new IllegalArgumentException("Property 'retryWait' must be a number");
		}

		str = getProperty(PROP_BINARY_ATTRIBUTES);
		if (StringUtils.isNotEmpty(str))
			builder.binaryAttributes(StringUtils.split(str));

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

}
