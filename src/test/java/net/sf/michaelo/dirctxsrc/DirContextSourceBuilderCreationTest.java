/*
 * Copyright 2013 Michael Osipov
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

import org.junit.Assert;
import org.junit.Test;

// $Id$
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
