package com.zonaunica.ZonaUnica.controllers;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.validation.Valid;

import com.zonaunica.ZonaUnica.Exceptions.CustomException;
import com.zonaunica.ZonaUnica.models.SitioTuristicoModel;
import com.zonaunica.ZonaUnica.services.SitioTuristicoService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.Errors;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin(origins = "*" )
@RequestMapping("/api")
public class SitioTuristicoController {
    
    @Autowired
    SitioTuristicoService sitioTuristicoService;

    @GetMapping("/sitios")
    public List<SitioTuristicoModel> traerSitios(){
        return sitioTuristicoService.traerSitios();
    }

    @GetMapping("/sitios/{id}")
    public SitioTuristicoModel obtenerById(@PathVariable("id") String id ){
        return sitioTuristicoService.buscarById(id).get();
    }

    @PostMapping("/sitios")
    public ResponseEntity<Map<String, String>> guardarSitio(@Valid @RequestBody SitioTuristicoModel sitio, Errors error){
        if(error.hasErrors()){
            throwError(error);
        }
        sitioTuristicoService.registrarSitio(sitio);
        Map<String, String> respuesta = new HashMap<>();
        respuesta.put("Mensaje", "El sitio se agregó correctamente");
        return ResponseEntity.ok(respuesta);
    }

    @PutMapping("/sitios")
    public ResponseEntity<Map<String, String>> actualizar(@RequestBody SitioTuristicoModel sitio, Errors error){
        if(error.hasErrors()){
            throwError(error);
        }

        sitioTuristicoService.registrarSitio(sitio);
        Map<String, String> respuesta= new HashMap<>();
        respuesta.put("Mensaje", "El sitio se actualizó correctamente");
        return ResponseEntity.ok(respuesta);
    }

    @DeleteMapping("/sitios/{id}")
    public ResponseEntity<Map<String, String>> eliminarById(@PathVariable String id){
        Boolean existe= sitioTuristicoService.existById(id);
        Map<String, String> respuesta = new HashMap<>();
        if(!existe){
            respuesta.put("Mensaje", "Este existe ese id ");
            return ResponseEntity.ok(respuesta);
        } 
        sitioTuristicoService.eliminarById(id);
        respuesta.put("Mensaje", "El id se eliminnó correctamente");
        return ResponseEntity.ok(respuesta); 
    }

    private void throwError(Errors error) {
        String message="";
        int index=0;
        for(ObjectError e: error.getAllErrors()){
            if(index>0){
                message += " | ";
            }
            message += String.format("Parametro: %s - Mensaje: %s", e.getObjectName(),e.getDefaultMessage());
        }
        throw new CustomException(message);
    }
}
