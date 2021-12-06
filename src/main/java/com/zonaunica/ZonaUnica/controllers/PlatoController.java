package com.zonaunica.ZonaUnica.controllers;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.validation.Valid;

import com.zonaunica.ZonaUnica.Exceptions.CustomException;
import com.zonaunica.ZonaUnica.models.PlatoModel;
import com.zonaunica.ZonaUnica.services.PlatoService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.Errors;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.*;


@RestController
@CrossOrigin(origins = "*" )
@RequestMapping("/api")
public class PlatoController {

    @Autowired
    PlatoService platoService;

    @PostMapping("/platos")
    public ResponseEntity<Map<String,String>> guardar(@Valid @RequestBody PlatoModel plato, Errors error){
        if(error.hasErrors()){
            throwError(error);
        }

        this.platoService.guardarPlato(plato);
        Map<String,String> response= new HashMap<>();
        response.put("mensaje", "Registro agregado correctamente");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/platos")
    public List<PlatoModel> traerTodos(){
        return this.platoService.obtnerPlatos();
    }

    @GetMapping("/platos/{id}")
    public PlatoModel buscarID(@PathVariable String id){
        return this.platoService.buscarPorId(id).get();
    }

    @DeleteMapping("/platos/{id}")
    public ResponseEntity<Map<String,String>> eliminarPorId(@PathVariable("id") String id){
        Boolean existe =  this.platoService.existById(id);
        Map<String, String> respuesta=new HashMap<>();
        if(!existe){
            respuesta.put("Mensaje","No existe el Registro con id");
            return ResponseEntity.ok(respuesta);
        }
        
        //Si existe pasa existe el valor solicitado salta y continua con la ejecución
        //de lo contrario entra en el condicional y devuelve el retorno y sale del metodo.
        
        platoService.eliminarPorId(id);
        respuesta.put("Mensaje", "Registro eliminado correctamente");
        return ResponseEntity.ok(respuesta);
    }
 
    @PutMapping("/platos")
    public ResponseEntity<Map<String, String>> actualizar(@RequestBody PlatoModel plato, Errors error){
        if(error.hasErrors()){
            throwError(error);
        }
        platoService.guardarPlato(plato);
        Map<String,String> respuesta=new HashMap<>();
        respuesta.put("Mensaje","La información de plato típico se ha actualizado");
        return ResponseEntity.ok(respuesta);
    }


    private void throwError(Errors error) {
        String message="";
        int index=0;
        for(ObjectError e: error.getAllErrors()){
            if(index>0){
                message += " | "; 
            }
            message += String.format("Parametro: %s - Mensaje: %s", e.getObjectName(), e.getDefaultMessage());
        }
        throw new CustomException(message);
    }

    
}
