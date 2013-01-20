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

	@Test(expected = SecurityException.class)
	public void gssApiAuthNoLoginConfFile() throws Throwable {
		DirContextSource.Builder builder = new DirContextSource.Builder(
				"ldap://localhost:11389");
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

		System.setProperty("java.security.auth.login.config",
				loginConfDirectory + System.getProperty("file.separator")
						+ "login.conf");

		DirContextSource.Builder builder = new DirContextSource.Builder(
				"ldap://localhost:11389");
		DirContextSource contextSource = builder.gssApiAuth("NonExistingEntry")
				.build();
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

		System.setProperty("java.security.auth.login.config",
				loginConfDirectory + System.getProperty("file.separator")
						+ "login.conf");

		DirContextSource.Builder builder = new DirContextSource.Builder(
				"ldap://localhost:11389");
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
