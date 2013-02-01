package net.sf.michaelo.dirctxsrc;

import org.apache.catalina.startup.Bootstrap;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class DirContextSourceFactoryTest {
	
	private Bootstrap bootstrap;
	
	@Before
	public void startTomcat() throws Exception {
		
		bootstrap = new Bootstrap();
		bootstrap.setCatalinaHome("H:\\Projekte\\dirctxsrc\\target\\test-classes\\tomcat6x-home");
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
