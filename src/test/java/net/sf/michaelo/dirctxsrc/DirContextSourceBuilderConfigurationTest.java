package net.sf.michaelo.dirctxsrc;

import static org.junit.Assert.*;
import org.junit.Test;

public class DirContextSourceBuilderConfigurationTest {

	private DirContextSource.Builder newInstance() {
		return new DirContextSource.Builder("ldap:///");
	}

	@Test
	public void configureContextFactory() {
		assertNotNull(newInstance().contextFactory(
				"net.sf.michaelo.dirctxsrc.NoOpFactory"));
	}

	@Test(expected = NullPointerException.class)
	public void nullObjectArgumentValidation() {
		newInstance().auth(null);
	}

	@Test(expected = NullPointerException.class)
	public void nullStringArgumentValidation() {
		newInstance().loginEntryName(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void emptyStringArgumentValidation() {
		newInstance().loginEntryName("");
	}

	@Test
	public void partialVaragsValidation() {
		assertNotNull(newInstance().objectFactories("valid", null, "",
				"valid.again"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void zeroIntegerValidation() {
		newInstance().retries(0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void negativeIntegerValidation() {
		newInstance().retryWait(-1);
	}

	@Test
	public void configureAnonAuth() {
		assertNotNull(newInstance().anonymousAuth());
	}

	@Test
	public void configureGssAuth() {
		assertNotNull(newInstance().gssApiAuth());
	}

	@Test
	public void configureGssAuthWithLoginEntryNAme() {
		assertNotNull(newInstance().gssApiAuth("JUnitTest"));
	}

	@Test
	public void configureObjectFactories() {
		assertNotNull(newInstance().objectFactories(
				"net.sf.michaelo.dirctxsrc.NoOpFactory",
				"net.sf.michaelo.dirctxsrc.SuperNoOpFactory"));
	}

	@Test
	public void configureMutualAuth() {
		assertNotNull(newInstance().mutualAuth());
	}

	@Test
	public void configureQops() {
		assertNotNull(newInstance().qops("auth-int", "auth-conf"));
	}

	@Test
	public void configureDebug() {
		assertNotNull(newInstance().debug());
	}

	@Test
	public void configureDisableDebug() {
		assertNotNull(newInstance().debug(false));
	}

	@Test
	public void configureDebugWithOutputStream() {
		assertNotNull(newInstance().debug(System.out));
	}

	@Test
	public void configureRetries() {
		assertNotNull(newInstance().retries(5));
	}

	@Test
	public void configureRetryWait() {
		assertNotNull(newInstance().retryWait(10000));
	}

	@Test
	public void configureBinaryAttributes() {
		assertNotNull(newInstance().binaryAttributes("objectGuid", "objectSid"));
	}

	@Test
	public void configureAdditionalProperty() {
		assertNotNull(newInstance().additionalProperty("magic", "shazam"));
	}
}
