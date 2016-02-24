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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;

import org.apache.catalina.startup.Bootstrap;
import org.apache.commons.io.IOUtils;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.DirectoryService;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import org.apache.directory.server.core.schema.SchemaPartition;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.shared.ldap.schema.SchemaManager;
import org.apache.directory.shared.ldap.schema.ldif.extractor.SchemaLdifExtractor;
import org.apache.directory.shared.ldap.schema.ldif.extractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.shared.ldap.schema.loader.ldif.LdifSchemaLoader;
import org.apache.directory.shared.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.shared.ldap.schema.registries.SchemaLoader;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

// $Id$
public class DirContextSourceFactoryTest {

	private static Bootstrap bootstrap;
	private static File catalinaHome;
	private static DirectoryService directoryService;
	private static LdapServer ldapServer;

	@BeforeClass
	public static void prepareEnv() throws Exception {
		String buildDirectory = System.getProperty("buildDirectory");

		/*
		 * Code taken and adapted from
		 * http://svn.apache.org/repos/asf/directory/documentation/samples/trunk/embedded-sample/
		 */
		File workingDirectory = new File(buildDirectory, "apacheds-work");
		workingDirectory.mkdir();

		directoryService = new DefaultDirectoryService();
		directoryService.setWorkingDirectory(workingDirectory);

		SchemaPartition schemaPartition = directoryService.getSchemaService().getSchemaPartition();

		LdifPartition ldifPartition = new LdifPartition();
		File schemaRepository = new File(workingDirectory, "schema");
		ldifPartition.setWorkingDirectory(schemaRepository.getPath());

		SchemaLdifExtractor extractor = new DefaultSchemaLdifExtractor(workingDirectory);
		extractor.extractOrCopy(true);

		schemaPartition.setWrappedPartition(ldifPartition);

		SchemaLoader loader = new LdifSchemaLoader(schemaRepository);
		SchemaManager schemaManager = new DefaultSchemaManager(loader);
		directoryService.setSchemaManager(schemaManager);

		schemaManager.loadAllEnabled();

		schemaPartition.setSchemaManager(schemaManager);

		List<Throwable> errors = schemaManager.getErrors();

		if (!errors.isEmpty())
			throw new Exception("Schema load failed: " + errors);

		JdbmPartition systemPartition = new JdbmPartition();
		systemPartition.setId("system");
		systemPartition.setPartitionDir(new File(directoryService.getWorkingDirectory(), "system"));
		systemPartition.setSuffix(ServerDNConstants.SYSTEM_DN);
		systemPartition.setSchemaManager(schemaManager);
		directoryService.setSystemPartition(systemPartition);

		directoryService.setShutdownHookEnabled(false);
		directoryService.getChangeLog().setEnabled(false);

		ldapServer = new LdapServer();
		ldapServer.setTransports(new TcpTransport(11389));
		ldapServer.setDirectoryService(directoryService);

		directoryService.startup();
		ldapServer.start();

		catalinaHome = new File(new File(buildDirectory, "test-classes"), "tomcat6x-home");
		bootstrap = new Bootstrap();
		bootstrap.setCatalinaHome(catalinaHome.getAbsolutePath());
		bootstrap.start();
	}

	@AfterClass
	public static void stopEnv() throws Exception {
		bootstrap.stop();
		ldapServer.stop();
		directoryService.shutdown();
		directoryService.getWorkingDirectory().delete();
	}

	@Test
	public void callDirContextSourceFromServlet() throws IOException {
		URL url = new URL("http://localhost:28888/dircontextsource/apacheds");
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.connect();
		InputStream is = conn.getInputStream();
		String content = IOUtils.toString(is, "UTF-8");
		System.out.println("Received from URL: " + content);
		Assert.assertNotNull(content);
		conn.disconnect();
	}

	@Test
	public void callDeadDirContextSourceFromServlet() throws IOException {
		URL url = new URL("http://localhost:28888/dircontextsource/dead");
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.connect();
		Assert.assertEquals(500, conn.getResponseCode());
		conn.disconnect();
	}

}
