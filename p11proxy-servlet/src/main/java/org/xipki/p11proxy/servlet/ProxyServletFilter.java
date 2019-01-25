/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.p11proxy.servlet;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.Securities;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.P11TokenException;
import org.xipki.util.InvalidConfException;
import org.xipki.util.LogUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public class ProxyServletFilter implements Filter {

  private static final Logger LOG = LoggerFactory.getLogger(ProxyServletFilter.class);

  private Securities securities;

  private HttpProxyServlet servlet;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    securities = new Securities();
    try {
      securities.init();
    } catch (IOException | InvalidConfException ex) {
      LogUtil.error(LOG, ex, "could not initializing Securities");
      return;
    }

    LocalP11CryptServicePool pool = new LocalP11CryptServicePool();
    pool.setP11CryptServiceFactory(securities.getP11CryptServiceFactory());
    try {
      pool.init();
    } catch (P11TokenException | XiSecurityException ex) {
      throw new ServletException(
          "could not initialize LocalP11CryptServicePool: " + ex.getMessage(), ex);
    }

    servlet = new HttpProxyServlet();
    servlet.setLocalP11CryptServicePool(pool);
  }

  @Override
  public void destroy() {
    if (securities != null) {
      securities.close();
    }
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (!(request instanceof HttpServletRequest & response instanceof HttpServletResponse)) {
      throw new ServletException("Only HTTP request is supported");
    }

    HttpServletRequest req = (HttpServletRequest) request;
    HttpServletResponse resp = (HttpServletResponse) response;
    servlet.doPost(req, resp);
  }

}