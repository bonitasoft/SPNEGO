/** 
 * Copyright (C) 2018 BonitaSoft S.A.
 * BonitaSoft, 32 rue Gustave Eiffel - 38000 Grenoble
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
package org.bonitasoft.web.server.auth.kerberos;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;

public class KerberosConfig implements FilterConfig {
	
    private final Properties properties;
    
    /**
     * Private constructor to prevent instantiation
     */
    public KerberosConfig(Properties properties) {
        this.properties = properties;
    }
    /**
     * Gets all Kerberos filter properties as a Map
     * @return Map
     */
    public Map<String,String> getAllAsMap()
    {
    	final Map<String,String> map = new HashMap<String, String>();
    	for (final String name: properties.stringPropertyNames())
    	    map.put(name, properties.getProperty(name));
    	return map;
    }

    public Properties getProperties() {
        return properties;
    }
    
    @Override
    public String getFilterName() {
        throw new UnsupportedOperationException();
    }
    
    @Override
    public ServletContext getServletContext() {
        throw new UnsupportedOperationException();
    }
    
    @Override
    public String getInitParameter(String name) {
        return properties.getProperty(name);
    }
    
    @SuppressWarnings("unchecked")
    @Override
    public Enumeration<String> getInitParameterNames() {
        return (Enumeration<String>) properties.propertyNames();
    }
}
