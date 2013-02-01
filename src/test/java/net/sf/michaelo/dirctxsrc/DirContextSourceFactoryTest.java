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

import java.io.File;

import org.apache.catalina.startup.Bootstrap;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

// $Id$
public class DirContextSourceFactoryTest {
	
	private Bootstrap bootstrap;
	private static File catalinaHome;
	
	@BeforeClass
	public static void prepareEnv() {
		String buildDirectory = System.getProperty("buildDirectory");
		catalinaHome = new File(new File(buildDirectory, "test-classes"), "tomcat6x-home");
	}
	
	@Before
	public void startTomcat() throws Exception {
		bootstrap = new Bootstrap();
		bootstrap.setCatalinaHome(catalinaHome.getAbsolutePath());
		bootstrap.start();
	}
	
	@After
	public void stopTomcat() throws Exception {
		bootstrap.stop();
	}
	
	@Test
	public void test() {
		System.out.println(bootstrap.getCatalinaBase());
	}

}
