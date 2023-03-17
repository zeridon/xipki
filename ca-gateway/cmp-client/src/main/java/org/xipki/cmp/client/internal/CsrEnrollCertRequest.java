// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client.internal;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.xipki.cmp.client.IdentifiedObject;

import static org.xipki.util.Args.notBlank;
import static org.xipki.util.Args.notNull;

/**
 * CMP request to enroll certificate for given CSR.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class CsrEnrollCertRequest extends IdentifiedObject {

  private final String certprofile;

  private final CertificationRequest csr;

  CsrEnrollCertRequest(String id, String certprofile, CertificationRequest csr) {
    super(id);
    this.certprofile = notBlank(certprofile, "certprofile");
    this.csr = notNull(csr, "csr");
  }

  CertificationRequest getCsr() {
    return csr;
  }

  String getCertprofile() {
    return certprofile;
  }

}
