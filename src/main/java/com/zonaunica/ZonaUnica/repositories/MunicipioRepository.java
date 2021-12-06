package com.zonaunica.ZonaUnica.repositories;

import com.zonaunica.ZonaUnica.models.MunicipioModel;

import org.springframework.data.mongodb.repository.MongoRepository;

public interface MunicipioRepository extends MongoRepository<MunicipioModel, String>{
    
}
