package net.sf.michaelo.dirctxsrc;

import org.junit.Assert;
import org.junit.Test;

public class DirContextSourceBuilderCreationTest {

	@Test(expected = NullPointerException.class)
	public void nullUrl() {
		new DirContextSource.Builder(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void emptyUrl() {
		new DirContextSource.Builder("");
	}

	@Test
	public void nullAdditionalUrlsIgnored() {
		Assert.assertNotNull(new DirContextSource.Builder("ldap:///",
				(String[]) null));
	}

	@Test
	public void someInvalidUrls() {
		Assert.assertNotNull(new DirContextSource.Builder("ldap://one",
				"ldap://two", "", null, "ldap://three"));
	}

	@Test
	public void validUrls() {
		Assert.assertNotNull(new DirContextSource.Builder("ldap://one",
				"ldap://two", "ldap://three"));
	}

}
