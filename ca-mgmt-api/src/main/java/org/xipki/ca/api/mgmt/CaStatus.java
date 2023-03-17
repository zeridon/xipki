// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.util.Args;

/**
 * CA status enum.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public enum CaStatus {

  ACTIVE("active"),
  INACTIVE("inactive");

  private final String status;

  CaStatus(String status) {
    this.status = status;
  }

  public String getStatus() {
    return status;
  }

  public static CaStatus forName(String status) {
    Args.notNull(status, "status");
    for (CaStatus value : values()) {
      if (value.status.equalsIgnoreCase(status)) {
        return value;
      }
    }

    throw new IllegalArgumentException("invalid CaStatus " + status);
  }

}
