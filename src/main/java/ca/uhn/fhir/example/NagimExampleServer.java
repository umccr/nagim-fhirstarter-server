package ca.uhn.fhir.example;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.server.RestfulServer;
import ca.uhn.fhir.rest.server.interceptor.CorsInterceptor;
import ca.uhn.fhir.rest.server.interceptor.ResponseHighlighterInterceptor;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Arrays;

@WebServlet("/*")
public class NagimExampleServer extends RestfulServer {

	//@Autowired
	//private PartitionSettings myPartitionSettings;

	@Override
	protected void initialize() throws ServletException {
		// Create a context for the appropriate version
		setFhirContext(FhirContext.forR4());

		/*{
			myPartitionSettings.setPartitioningEnabled(true);

			// Set the tenant identification strategy
			setTenantIdentificationStrategy(new UrlBaseTenantIdentificationStrategy());

			// Use the tenant ID supplied by the tenant identification strategy
			// to serve as the partitioning ID
			registerInterceptor(new RequestTenantPartitionInterceptor());
		} */

		// CORS
		{
			CorsConfiguration config = new CorsConfiguration();
			config.addAllowedHeader("Origin");
			config.addAllowedHeader("Accept");
			config.addAllowedHeader("Content-Type");
			config.setAllowCredentials(true);

			config.addAllowedOrigin("*");

			config.addExposedHeader("Location");
			config.addExposedHeader("Content-Location");
			config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));

			// Create the interceptor and register it
			CorsInterceptor interceptor = new CorsInterceptor(config);
			registerInterceptor(interceptor);
		}

		// Register resource providers
		registerProvider(new AghaPatientResourceProvider());

		registerInterceptor(new PassportVisaAuthorizationInterceptor());

		// Format the responses in nice HTML
		registerInterceptor(new ResponseHighlighterInterceptor());
	}
}
