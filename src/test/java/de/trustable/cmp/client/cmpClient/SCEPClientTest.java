package de.trustable.cmp.client.cmpClient;

import de.trustable.scep.client.scepClient.SCEPClient;
import junit.framework.Assert;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * Unit test for cmp client.
 */
public class SCEPClientTest
    extends TestCase
{
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public SCEPClientTest(String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( SCEPClientTest.class );
    }

    /**
     * Test of command args processing
     */
    public void testApp() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
    	String[] emptyArgs = {};
		int ret = SCEPClient.handleArgs(emptyArgs);
		Assert.assertEquals("arguments required", 1, ret);
		
    	String[] args = {"-h"};
		ret = SCEPClient.handleArgs(args);
		Assert.assertEquals("help is a valid option ", 0, ret);		
    }
}
