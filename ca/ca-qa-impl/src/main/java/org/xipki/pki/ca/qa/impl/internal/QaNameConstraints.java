/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.qa.impl.internal;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.xipki.pki.ca.certprofile.x509.jaxb.GeneralSubtreeBaseType;
import org.xipki.pki.ca.certprofile.x509.jaxb.NameConstraints;
import org.xipki.common.util.CollectionUtil;

/**
 * @author Lijun Liao
 */

public class QaNameConstraints extends QaExtension
{
    private final List<QaGeneralSubtree> permittedSubtrees;
    private final List<QaGeneralSubtree> excludedSubtrees;

    public QaNameConstraints(
            final NameConstraints jaxb)
    {
        if(jaxb.getPermittedSubtrees() != null
                && CollectionUtil.isNotEmpty(jaxb.getPermittedSubtrees().getBase()))
        {
            List<QaGeneralSubtree> list = new LinkedList<>();
            List<GeneralSubtreeBaseType> bases =  jaxb.getPermittedSubtrees().getBase();
            for(GeneralSubtreeBaseType base : bases)
            {
                list.add(new QaGeneralSubtree(base));
            }
            this.permittedSubtrees = Collections.unmodifiableList(list);
        } else
        {
            permittedSubtrees = null;
        }

        if(jaxb.getExcludedSubtrees() != null
                && CollectionUtil.isNotEmpty(jaxb.getExcludedSubtrees().getBase()))
        {
            List<QaGeneralSubtree> list = new LinkedList<>();
            List<GeneralSubtreeBaseType> bases =  jaxb.getExcludedSubtrees().getBase();
            for(GeneralSubtreeBaseType base : bases)
            {
                list.add(new QaGeneralSubtree(base));
            }
            this.excludedSubtrees = Collections.unmodifiableList(list);
        } else
        {
            excludedSubtrees = null;
        }

        if(permittedSubtrees == null && excludedSubtrees == null)
        {
            throw new IllegalArgumentException(
                    "at least one of permittedSubtrees and excludesSubtrees should be non-null");
        }
    }

    public List<QaGeneralSubtree> getPermittedSubtrees()
    {
        return permittedSubtrees;
    }

    public List<QaGeneralSubtree> getExcludedSubtrees()
    {
        return excludedSubtrees;
    }

}
