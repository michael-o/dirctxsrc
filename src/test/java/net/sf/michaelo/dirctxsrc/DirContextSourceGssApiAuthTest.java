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

import java.io.File;
import java.util.Properties;

import javax.naming.NamingException;
import javax.security.auth.login.LoginException;

import org.junit.BeforeClass;
import org.junit.Test;

public class DirContextSourceGssApiAuthTest {

	private static File loginConfDirectory;

	@BeforeClass
	public static void startApacheDs() throws Exception {
		String buildDirectory = System.getProperty("buildDirectory");
		loginConfDirectory = new File(buildDirectory, "test-classes");
	}

	@Test(expected = LoginException.class)
	public void gssApiAuthNoLoginConfFile() throws Throwable {
		DirContextSource.Builder builder = new DirContextSource.Builder("ldap://localhost:11389");
		DirContextSource contextSource = builder.gssApiAuth().build();
		try {
			contextSource.getDirContext();
		} catch (NamingException e) {
			throw e.getCause();
		}
	}

	@Test(expected = LoginException.class)
	public void gssApiAuthNoLoginEntryNameInConfFile() throws Throwable {

		Properties systemProperties = new Properties();
		systemProperties.putAll(System.getProperties());

		System.setProperty(
				"java.security.auth.login.config", new File(loginConfDirectory, "login.conf").getAbsolutePath());

		DirContextSource.Builder builder = new DirContextSource.Builder("ldap://localhost:11389");
		DirContextSource contextSource = builder.gssApiAuth("NonExistingEntry").build();
		try {
			contextSource.getDirContext();
		} catch (NamingException e) {
			throw e.getCause();
		} finally {
			System.setProperties(systemProperties);
		}
	}

	@Test(expected = LoginException.class)
	public void gssApiAuthLoginEntryNameInConfFile() throws Throwable {

		Properties systemProperties = new Properties();
		systemProperties.putAll(System.getProperties());

		System.setProperty(
				"java.security.auth.login.config", new File(loginConfDirectory, "login.conf").getAbsolutePath());

		DirContextSource.Builder builder = new DirContextSource.Builder("ldap://localhost:11389");
		DirContextSource contextSource = builder.gssApiAuth().build();
		try {
			contextSource.getDirContext();
		} catch (NamingException e) {
			throw e.getCause();
		} finally {
			System.setProperties(systemProperties);
		}
	}
}
