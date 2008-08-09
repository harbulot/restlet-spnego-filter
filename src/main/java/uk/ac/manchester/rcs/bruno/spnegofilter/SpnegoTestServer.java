/*

Copyright (c) 2008, The University of Manchester, United Kingdom.
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.
    * Neither the name of the The University of Manchester nor the names of 
      its contributors may be used to endorse or promote products derived 
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGE.

 */
package uk.ac.manchester.rcs.bruno.spnegofilter;

import java.security.Principal;
import java.util.Map;
import java.util.Map.Entry;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

import org.restlet.Application;
import org.restlet.Component;
import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.Router;
import org.restlet.data.MediaType;
import org.restlet.data.Protocol;
import org.restlet.data.Request;
import org.restlet.data.Response;
import org.restlet.resource.Representation;
import org.restlet.resource.Resource;
import org.restlet.resource.ResourceException;
import org.restlet.resource.StringRepresentation;
import org.restlet.resource.Variant;

/**
 * @author Bruno Harbulot
 */
public class SpnegoTestServer {
	public static class HelloPrincipalResource extends Resource {
		private Principal principal;
	    public HelloPrincipalResource(Context context, Request request,
	            Response response) {
	        super(context, request, response);
	        
	        principal = (Principal)request.getAttributes().get("ThePrincipal");

	        getVariants().add(new Variant(MediaType.TEXT_PLAIN));
	    }

	    @Override
	    public Representation represent(Variant variant) throws ResourceException {
	        Representation representation = new StringRepresentation(
	                "Hello "+(principal!=null?principal.getName():"")+"!", MediaType.TEXT_PLAIN);
	        return representation;
	    }
	}
	
	public static class SpnegoTestApplication extends Application {
	    @Override
	    public synchronized Restlet createRoot() {
	        try {
				Router router = new Router(getContext());

				router.attachDefault(HelloPrincipalResource.class);
				
				SpnegoFilter filter = new SpnegoFilter("server");
				//filter.gssInit();
				filter.setNext(router);

				return filter;
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
	    }
	}
	
	public static void main(String[] args) throws Exception {
		Configuration secConfig = Configuration.getConfiguration();
		AppConfigurationEntry[] secConfEntries = secConfig.getAppConfigurationEntry("server");
		
		
		for (AppConfigurationEntry secConfEntry: secConfEntries) {
			System.out.println("AppConfigurationEntry: "+secConfEntry);
			Map<String, ?> options = secConfEntry.getOptions();
			for (Entry<String,?> entry: options.entrySet()) {
				System.out.println(" option...    "+entry.getKey()+" = "+entry.getValue());
			}
		}
		
        Component component = new Component();

        component.getServers().add(Protocol.HTTP, 8182);

        component.getDefaultHost().attach(
                new SpnegoTestApplication());

        component.start();
	}

}
