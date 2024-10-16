// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ocsp;

import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
import org.xipki.util.TripleState;

/**
 * OCSP response option.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class OcspResponseOption {

  private X509Cert respIssuer;

  private TripleState nonceOccurrence;

  private TripleState nextUpdateOccurrence;

  private SignAlgo signatureAlg;

  public OcspResponseOption() {
  }

  public X509Cert getRespIssuer() {
    return respIssuer;
  }

  public void setRespIssuer(X509Cert respIssuer) {
    this.respIssuer = respIssuer;
  }

  public TripleState getNonceOccurrence() {
    return nonceOccurrence;
  }

  public void setNonceOccurrence(TripleState nonceOccurrence) {
    this.nonceOccurrence = nonceOccurrence;
  }

  public TripleState getNextUpdateOccurrence() {
    return nextUpdateOccurrence;
  }

  public void setNextUpdateOccurrence(TripleState nextUpdateOccurrence) {
    this.nextUpdateOccurrence = nextUpdateOccurrence;
  }

  public SignAlgo getSignatureAlg() {
    return signatureAlg;
  }

  public void setSignatureAlg(SignAlgo signatureAlg) {
    this.signatureAlg = signatureAlg;
  }

}
