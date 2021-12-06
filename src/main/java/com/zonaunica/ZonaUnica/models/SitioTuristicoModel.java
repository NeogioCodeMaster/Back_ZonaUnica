package com.zonaunica.ZonaUnica.models;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "SitiosTuristicos")
public class SitioTuristicoModel {
    @Id
    private String id;
    private String nombre;
    private String descripcion;
    private UsuarioModel usuario;
    private PlatoModel plato;
    private MunicipioModel municipio;
    
    
    public String getId() {
        return id;
    }
    public void setId(String id) {
        this.id = id;
    }
    public String getNombre() {
        return nombre;
    }
    public void setNombre(String nombre) {
        this.nombre = nombre;
    }
    public String getDescripcion() {
        return descripcion;
    }
    public void setDescripcion(String descripcion) {
        this.descripcion = descripcion;
    }
    public UsuarioModel getUsuario() {
        return usuario;
    }
    public void setUsuario(UsuarioModel usuario) {
        this.usuario = usuario;
    }
    public PlatoModel getPlato() {
        return plato;
    }
    public void setPlato(PlatoModel plato) {
        this.plato = plato;
    }
    public MunicipioModel getMunicipio() {
        return municipio;
    }
    public void setMunicipio(MunicipioModel municipio) {
        this.municipio = municipio;
    }

    
}
