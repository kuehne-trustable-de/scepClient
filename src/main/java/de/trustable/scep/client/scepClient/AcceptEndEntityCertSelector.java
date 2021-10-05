package de.trustable.scep.client.scepClient;

import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class AcceptEndEntityCertSelector implements CertSelector {

	@Override
	public boolean match(Certificate cert) {
		if( cert instanceof X509Certificate){
			return ((X509Certificate) cert).getBasicConstraints() == -1;
		}
		return false;
	}

	@Override
	public CertSelector clone() {
		return null;
	}

}