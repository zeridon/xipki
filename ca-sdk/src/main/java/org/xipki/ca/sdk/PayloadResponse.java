// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.security.util.JSON;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class PayloadResponse extends SdkResponse {

  /**
   * payload.
   */
  private byte[] payload;

  public byte[] getPayload() {
    return payload;
  }

  public void setPayload(byte[] payload) {
    this.payload = payload;
  }

  public static PayloadResponse decode(byte[] encoded) {
    return JSON.parseObject(encoded, PayloadResponse.class);
  }

}
