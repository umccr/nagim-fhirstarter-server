# HAPI FHIR Plain Server Skeleton

## UMCCR Notes

This is a starter project from HAPI.

We are using it as a playground for experimentation with passports/visas.

The main additions are:

- upgrading some of the build artifacts to newer Java/Maven/Jetty etc
- adding an interceptor that understands passport/visas
- fake patient data

There is also a CDK project that deploys the server to AWS behind an ALB.


## Original README

To try this project out:

* Run the following command to compile the project and start a local testing server that runs it:

```
mvn jetty:run
```

* Test that your server is running by fetching its CapabilityStatement:

   http://localhost:8080/metadata

* Try reading back a resource from your server using the following URL:

   http://localhost:8080/Patient/1

* Try reading back a resource that does not exist by using the following URL:

   http://localhost:8080/Patient/999

The responses to the Patient read operations above come from the resource provider called [Example01_PatientResourceProvider.java](https://github.com/FirelyTeam/fhirstarters/blob/master/java/hapi-fhirstarters-simple-server/src/main/java/ca/uhn/fhir/example/Example01_PatientResourceProvider.java)

