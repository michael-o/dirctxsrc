package net.sf.michaelo.dirctxsrc;

import static org.junit.Assert.*;
import net.sf.michaelo.dirctxsrc.DirContextSource.Auth;

import org.junit.Test;

public class DirContextSourceBuilderTest {

	private DirContextSource.Builder newInstance() {
		return new DirContextSource.Builder("ldap:///");
	}

	@Test
	public void buildDirContextSource() {
		DirContextSource.Builder builder = newInstance();
		assertNotNull(builder.build());
	}

	@Test(expected = IllegalStateException.class)
	public void buildWithIncompleteGssApiConfig() {
		DirContextSource.Builder builder = newInstance();
		builder.auth(Auth.GSSAPI);
		builder.build();
	}

	@Test
	public void buildWithCompleteGssApiConfig() {
		DirContextSource.Builder builder = newInstance();
		builder.auth(Auth.GSSAPI).loginEntryName("JUnitTest");
		assertNotNull(builder.build());
	}

	@Test(expected = IllegalStateException.class)
	public void reconfigureFinishedBuilder() {
		DirContextSource.Builder builder = newInstance();
		builder.build();
		builder.debug();
	}

}
