/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security.pkcs11;

import org.xipki.util.CompareUtil;

import java.util.*;

import static org.xipki.util.Args.notNull;

/**
 * PKCS#11 module.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P11Module {

  protected final P11ModuleConf conf;

  private final Map<P11SlotId, P11Slot> slots = new HashMap<>();

  private final List<P11SlotId> slotIds = new ArrayList<>();

  public P11Module(P11ModuleConf conf) {
    this.conf = notNull(conf, "conf");
  }

  public abstract void close();

  public abstract String getDescription();

  public String getName() {
    return conf.getName();
  }

  public boolean isReadOnly() {
    return conf.isReadOnly();
  }

  public P11ModuleConf getConf() {
    return conf;
  }

  protected void setSlots(Set<P11Slot> slots) {
    this.slots.clear();
    this.slotIds.clear();
    for (P11Slot slot : slots) {
      this.slots.put(slot.getSlotId(), slot);
      this.slotIds.add(slot.getSlotId());
    }

    Collections.sort(this.slotIds);
  }

  /**
   * Returns slot for the given {@code slotId}.
   *
   * @param slotId
   *          slot identifier. Must not be {@code null}.
   * @return the slot
   * @throws P11TokenException
   *         if PKCS#11 token error occurs
   */
  public P11Slot getSlot(P11SlotId slotId) throws P11UnknownEntityException {
    notNull(slotId, "slotId");
    P11Slot slot = slots.get(slotId);
    if (slot == null) {
      throw new P11UnknownEntityException(slotId);
    }
    return slot;
  } // method getSlot

  void destroySlot(long slotId) {
    P11SlotId p11SlotId = null;
    for (P11SlotId si : slots.keySet()) {
      if (CompareUtil.equalsObject(si.getId(), slotId)) {
        p11SlotId = si;
        break;
      }
    }
    if (p11SlotId != null) {
      slots.remove(p11SlotId);
    }
  }

  public List<P11SlotId> getSlotIds() {
    return slotIds;
  }

  public P11SlotId getSlotIdForIndex(int index) throws P11UnknownEntityException {
    for (P11SlotId id : slotIds) {
      if (id.getIndex() == index) {
        return id;
      }
    }
    throw new P11UnknownEntityException("could not find slot with index " + index);
  }

  public P11SlotId getSlotIdForId(long id) throws P11UnknownEntityException {
    for (P11SlotId slotId : slotIds) {
      if (slotId.getId() == id) {
        return slotId;
      }
    }
    throw new P11UnknownEntityException("could not find slot with id " + id);
  }

}
