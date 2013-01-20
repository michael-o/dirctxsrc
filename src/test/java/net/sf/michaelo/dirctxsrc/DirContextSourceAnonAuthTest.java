package net.sf.michaelo.dirctxsrc;

import java.io.File;
import java.util.List;

import javax.naming.CommunicationException;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;

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
import org.junit.Test;

import static org.junit.Assert.*;
import org.junit.BeforeClass;

public class DirContextSourceAnonAuthTest {

	private static DirectoryService directoryService;
	private static LdapServer ldapServer;

	/*
	 * Code taken and adapted from
	 * http://svn.apache.org/repos/asf/directory/documentation/samples/trunk/embedded-sample/
	 */
	@BeforeClass
	public static void startApacheDs() throws Exception {
		String buildDirectory = System.getProperty("buildDirectory");
		File workingDirectory = new File(buildDirectory, "apacheds-work");
		workingDirectory.mkdir();

		directoryService = new DefaultDirectoryService();
		directoryService.setWorkingDirectory(workingDirectory);

		SchemaPartition schemaPartition = directoryService.getSchemaService()
				.getSchemaPartition();

		LdifPartition ldifPartition = new LdifPartition();
		File schemaRepository = new File(workingDirectory, "schema");
		ldifPartition.setWorkingDirectory(schemaRepository.getPath());

		SchemaLdifExtractor extractor = new DefaultSchemaLdifExtractor(
				workingDirectory);
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
		systemPartition.setPartitionDir(new File(directoryService
				.getWorkingDirectory(), "system"));
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
	}

	@AfterClass
	public static void stopApacheDs() throws Exception {
		ldapServer.stop();
		directoryService.shutdown();
		directoryService.getWorkingDirectory().delete();
	}

	@Test
	public void anonAuth() throws NamingException {
		DirContextSource.Builder builder = new DirContextSource.Builder(
				"ldap://localhost:11389");
		DirContextSource contextSource = builder.build();

		DirContext context = contextSource.getDirContext();
		assertTrue(context.getAttributes("").get("objectClass").size() == 2);
		context.close();
	}

	@Test(expected = CommunicationException.class)
	public void anonAuthWithDeadServer() throws NamingException {
		DirContextSource.Builder builder = new DirContextSource.Builder(
				"ldap://localhost:11390");
		DirContextSource contextSource = builder.build();
		DirContext context = contextSource.getDirContext();
		context.close();
	}

	@Test
	public void anonAuthFullyConfigured() throws NamingException {
		DirContextSource.Builder builder = new DirContextSource.Builder(
				"ldap://localhost:11389");
		builder.debug().binaryAttributes("objectSid").qops("auth")
				.objectFactories("net.sf.michaelo.dirctxsrc.NoOpFactory");
		DirContextSource contextSource = builder.build();

		DirContext context = contextSource.getDirContext();
		assertTrue(context.getAttributes("").get("objectClass").size() == 2);
		context.close();
	}

}
