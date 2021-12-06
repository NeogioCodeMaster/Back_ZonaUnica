package com.zonaunica.ZonaUnica.repositories;

import java.util.Optional;

import com.zonaunica.ZonaUnica.models.PlatoModel;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PlatoRepository extends MongoRepository<PlatoModel, String>{

    public Optional<PlatoModel> findByNombre(String nombre);

}
    
