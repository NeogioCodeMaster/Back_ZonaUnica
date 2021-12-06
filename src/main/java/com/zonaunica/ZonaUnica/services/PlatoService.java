package com.zonaunica.ZonaUnica.services;

import java.util.List;
import java.util.Optional;

import com.zonaunica.ZonaUnica.models.PlatoModel;
import com.zonaunica.ZonaUnica.repositories.PlatoRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class PlatoService {
    
    @Autowired
    PlatoRepository platoRepository;
    
    public void guardarPlato(PlatoModel plato){
        this.platoRepository.save(plato);
    }

    public List<PlatoModel> obtnerPlatos(){
        return this.platoRepository.findAll();
    }

    public Boolean existById(String id){
        return this.platoRepository.existsById(id);
    }

    public Optional<PlatoModel> buscarPorId(String id){
        return this.platoRepository.findById(id);
    }

    public PlatoModel buscarPorNombrePlato(String nombre){
        return this.platoRepository.findByNombre(nombre).orElse(new PlatoModel());
      }
  

    public void eliminarPorId(String id){
        this.platoRepository.deleteById(id);
    }

   




}
