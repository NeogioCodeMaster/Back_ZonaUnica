package com.zonaunica.ZonaUnica.services;

import java.util.List;
import java.util.Optional;


import com.zonaunica.ZonaUnica.models.UsuarioModel;
import com.zonaunica.ZonaUnica.repositories.UsuarioRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UsuarioService {
    
    @Autowired
    UsuarioRepository usuarioRepository;
   
    public void guardarUsuario(UsuarioModel usuario) {
        this.usuarioRepository.save(usuario);
    }
   
    public List<UsuarioModel> traerTodos() {
        return this.usuarioRepository.findAll();
    }
   
    public Optional<UsuarioModel> buscarPorId(String id) {
        return this.usuarioRepository.findById(id);
    }
    
    public UsuarioModel buscarUsername(String username) {
        return this.usuarioRepository.findByUsername(username).orElse(new UsuarioModel());
    }

    public Boolean existById(String id){
        return this.usuarioRepository.existsById(id);
    }
    public void eliminarPorId(String id){
        this.usuarioRepository.deleteById(id);
    }
}
