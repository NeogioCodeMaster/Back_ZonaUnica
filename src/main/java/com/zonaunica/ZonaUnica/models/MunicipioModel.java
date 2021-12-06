package com.zonaunica.ZonaUnica.models;

import org.springframework.data.mongodb.core.mapping.Document;
import javax.validation.constraints.NotEmpty;

import org.springframework.data.annotation.Id;

@Document(collection = "municipio")
public class MunicipioModel {
    
    @Id
    private String id;
    
    @NotEmpty(message="Este campo no puede quedar vacio")
    private String nombre;
    
    private String descripcion;
    private String fotos;
   
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
}
