package ca.uhn.fhir.example;

import ca.uhn.fhir.rest.annotation.IdParam;
import ca.uhn.fhir.rest.annotation.Read;
import ca.uhn.fhir.rest.annotation.Search;
import ca.uhn.fhir.rest.server.IResourceProvider;
import ca.uhn.fhir.rest.server.exceptions.ResourceNotFoundException;
import org.hl7.fhir.r4.model.*;
import org.hl7.fhir.instance.model.api.IBaseResource;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import java.time.LocalDate;
import java.time.Month;
import java.util.*;

public class AghaPatientResourceProvider implements IResourceProvider {

   private static final Logger logger
           = LoggerFactory.getLogger(AghaPatientResourceProvider.class);

   private final Map<String, Patient> myPatients = new HashMap<String, Patient>();
   private final Map<String, List<IBaseResource>> myCompartment = new HashMap<>();

   /**
    * Constructor
    */
   public AghaPatientResourceProvider() {
      {
         String id = "SINGLETONMARY";
         Patient p = new Patient();

         p.setId(new IdType("Patient", id));
         p.addIdentifier().setSystem("http://acme.com/MRNs").setValue("7000135");
         p.setBirthDate(new Date(76, Calendar.DECEMBER, 23));
         p.setGender(Enumerations.AdministrativeGender.FEMALE);
         p.addName().setFamily("Smith").addGiven("Mary");
         myPatients.put(id, p);
         myCompartment.put(id, new ArrayList<IBaseResource>());

          myCompartment.get(id).add(new Specimen().setSubject(new Reference(p)).setId("Specimen/HG00096"));

      }
      {
         Patient p = new Patient();

         p.setId("SINGLETONBRUCE");
         p.addName().setFamily("Yardley").addGiven("Bruce");
         p.setBirthDate(new Date(86, Calendar.MARCH, 13));
         p.setGender(Enumerations.AdministrativeGender.MALE);
         myPatients.put(p.getId(), p);
         myCompartment.put(p.getId(), new ArrayList<IBaseResource>());

         myCompartment.get(p.getId()).add(new Specimen().setSubject(new Reference(p)).setId("HG00097"));
      }
      {
         Patient p = new Patient();

         p.setId("SINGLETONSCOTT");
         p.addName().setFamily("Sterling").addGiven("Scott");
         p.setBirthDate(new Date(60, Calendar.FEBRUARY, 3));
         p.setGender(Enumerations.AdministrativeGender.MALE);
         myPatients.put(p.getId(), p);
         myCompartment.put(p.getId(), new ArrayList<IBaseResource>());

         myCompartment.get(p.getId()).add(new Specimen().setSubject(new Reference(p)).setId("HG00099"));
      }
      {
         Patient p = new Patient();

         p.setId("TRIOBART");
         p.addName().setFamily("Simpsons").addGiven("Bart");
         p.setBirthDate(new Date(80, Calendar.APRIL, 1));
         p.setGender(Enumerations.AdministrativeGender.MALE);
         myPatients.put(p.getId(), p);
         myCompartment.put(p.getId(), new ArrayList<IBaseResource>());
      }
      {
         Patient p = new Patient();

         p.setId("TRIOHOMER");
         p.addName().setFamily("Simpsons").addGiven("Homer");
         p.setBirthDate(new Date(56, Calendar.MAY, 12));
         p.setGender(Enumerations.AdministrativeGender.MALE);
         myPatients.put(p.getId(), p);
         myCompartment.put(p.getId(), new ArrayList<IBaseResource>());
      }
      {
         Patient p = new Patient();

         p.setId("TRIOMARGE");
         p.addName().setFamily("Simpsons").addGiven("Marge");
         p.setBirthDate(new Date(56, Calendar.MARCH, 19));
         p.setGender(Enumerations.AdministrativeGender.FEMALE);
         myPatients.put(p.getId(), p);
         myCompartment.put(p.getId(), new ArrayList<IBaseResource>());
      }
      {
         Patient p = new Patient();

         p.setId("PUBLICLISA");
         p.addName().setFamily("Simpsons").addGiven("Lisa");
         p.setBirthDate(new Date(82, Calendar.MAY, 9));
         p.setGender(Enumerations.AdministrativeGender.FEMALE);
         myPatients.put(p.getId(), p);
         myCompartment.put(p.getId(), new ArrayList<IBaseResource>());
      }
   }

   @Override
   public Class<? extends IBaseResource> getResourceType() {
      return Patient.class;
   }

   @Search(compartmentName="All")
   public List<IBaseResource> searchCompartmentForAll(@IdParam IdType thePatientId) {
      return new ArrayList<IBaseResource>(myCompartment.get(thePatientId.getIdPart()));
   }

   @Search(compartmentName="Specimen")
   public List<IBaseResource> searchCompartmentForSpecimen(@IdParam IdType thePatientId) {
      List<IBaseResource> retVal=new ArrayList<IBaseResource>();

      for (IBaseResource ibr : myCompartment.get(thePatientId.getIdPart()))
         if (Objects.equals(ibr.fhirType(), "Specimen"))
            retVal.add(ibr);

      return retVal;
   }

   /**
    * Simple implementation of the "read" method
    */
   @Read()
   public Patient read(@IdParam IdType theId) {
      Patient retVal = myPatients.get(theId.getIdPart());
      if (retVal == null) {
         throw new ResourceNotFoundException(theId);
      }
      return retVal;
   }


}
