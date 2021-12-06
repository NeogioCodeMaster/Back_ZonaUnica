package com.zonaunica.ZonaUnica.services;

import java.util.List;
import java.util.Optional;

import com.zonaunica.ZonaUnica.models.SitioTuristicoModel;
import com.zonaunica.ZonaUnica.repositories.SitioTuristicoRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SitioTuristicoService {
    
    @Autowired
    SitioTuristicoRepository sitioTuristicoRepository;

    public void registrarSitio(SitioTuristicoModel sitio){
        sitioTuristicoRepository.save(sitio);
    }

    public List<SitioTuristicoModel> traerSitios(){
        return sitioTuristicoRepository.findAll();
    }

    public Boolean existById(String id){
        return sitioTuristicoRepository.existsById(id);
    }

    public Optional<SitioTuristicoModel> buscarById(String id){
        return sitioTuristicoRepository.findById(id);
    }

    public void eliminarById(String id){
        sitioTuristicoRepository.deleteById(id);
    }
}
