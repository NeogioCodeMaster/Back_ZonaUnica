package com.zonaunica.ZonaUnica.models;

import javax.validation.constraints.NotEmpty;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "platos")
public class PlatoModel {
   
    @Id
    private String id;
    
    @NotEmpty(message="Este campo no puede quedar vacio")
    private String nombre;
    
    private String descripcion;
    private String fotos;
    private SitioTuristicoModel sitio;
    
    
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
    public String getFotos() {
        return fotos;
    }
    public void setFotos(String fotos) {
        this.fotos = fotos;
    }
    public SitioTuristicoModel getSitio() {
        return sitio;
    }
    public void setSitio(SitioTuristicoModel sitio) {
        this.sitio = sitio;
    }
}
