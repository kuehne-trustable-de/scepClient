package de.trustable.scep.client.scepClient;

import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class AcceptIssuerCertSelector implements CertSelector {

	X509Certificate issuedCert = null;

	public AcceptIssuerCertSelector(Certificate cert){
		if( cert instanceof X509Certificate) {
			issuedCert = (X509Certificate) cert;
		}
	}

	@Override
	public boolean match(Certificate cert) {
		if( cert instanceof X509Certificate){
			return issuedCert.getIssuerDN().equals(((X509Certificate) cert).getSubjectDN());
		}
		return false;
	}

	@Override
	public CertSelector clone() {
		return null;
	}

}