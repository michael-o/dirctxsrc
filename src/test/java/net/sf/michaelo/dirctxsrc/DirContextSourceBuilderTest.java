/*
 * Copyright 2013–2014 Michael Osipov
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

import static org.junit.Assert.*;
import net.sf.michaelo.dirctxsrc.DirContextSource.Auth;

import org.junit.Test;

// $Id$
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
