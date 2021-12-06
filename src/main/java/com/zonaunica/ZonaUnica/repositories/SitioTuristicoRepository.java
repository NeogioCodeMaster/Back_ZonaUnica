package com.zonaunica.ZonaUnica.repositories;

import com.zonaunica.ZonaUnica.models.SitioTuristicoModel;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SitioTuristicoRepository extends MongoRepository<SitioTuristicoModel, String> {
    
}
