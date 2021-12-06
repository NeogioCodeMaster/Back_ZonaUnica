package com.zonaunica.ZonaUnica.controllers;

import java.sql.Date;
import java.util.HashMap;
import java.util.Map;

import javax.validation.Valid;

import com.zonaunica.ZonaUnica.Exceptions.CustomException;
import com.zonaunica.ZonaUnica.models.UsuarioModel;
import com.zonaunica.ZonaUnica.services.UsuarioService;
import com.zonaunica.ZonaUnica.utils.Autorizacion;
import com.zonaunica.ZonaUnica.utils.BCrypt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.Errors;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@RestController
@CrossOrigin(origins = "http://localhost:4200" )
@RequestMapping("/api")
public class UsuarioController {
    
    @Autowired
    UsuarioService usuarioService;

    
     /**
     * Método para realizar la comprobación del token
     */
    @GetMapping("/verificar") //Ruta para acceder al método
    public ResponseEntity<Map<String, Boolean>> validarToken(){ //Retorna un Boolean
        Map<String, Boolean> respuesta=new HashMap<>();
        respuesta.put("ok",true); // Agrego la respuesta al MAP
        return ResponseEntity.ok(respuesta); 
    }


    // Registrar usuario
    @PostMapping("/usuarios")
    public ResponseEntity<Map<String, String>> guardarUsuario(@Valid @RequestBody UsuarioModel usuario, Errors error) {
        if (error.hasErrors()) {
            throwError(error);
        }
        Map<String, String> respuesta = new HashMap<>();
    //Contraseña sin cifrar 123456
        usuario.setPassword(BCrypt.hashpw(usuario.getPassword(), BCrypt.gensalt()));
    //Contraseña cifrada asfdffdgfghbvnhkhjkjh
        UsuarioModel u = this.usuarioService.buscarUsername(usuario.getUsername());

        if (u.getId() == null) {
            this.usuarioService.guardarUsuario(usuario);
            respuesta.put("Mensaje:", "Se resgistro el usuario correctamente");
        } else {
            respuesta.put("Mensaje:", "El usuario ya se encuentra registrado");
        }
        return ResponseEntity.ok(respuesta);
    }

    @PostMapping("/usuarios/login")
    public ResponseEntity<UsuarioModel> login(@RequestBody UsuarioModel usuario){
        UsuarioModel u=this.usuarioService.buscarUsername(usuario.getUsername());
        if(u.getUsername()==null){
            throw new CustomException("Usuario incorrectos");
        }

        if(!BCrypt.checkpw(usuario.getPassword(), u.getPassword())){
            throw new CustomException("Contraseña incorrectos");
        }

        String hash="";
        long tiempo = System.currentTimeMillis();
        if(u.getId()!=""){
            hash=Jwts.builder()
            .signWith(SignatureAlgorithm.HS256, Autorizacion.KEY)
            .setSubject(u.getNombre())
            .setIssuedAt(new Date(tiempo))
            .setExpiration(new Date(tiempo+9000000))
            .claim("username", u.getUsername())
            .claim("correo", u.getCorreo())
            .claim("rol", u.getCorreo())
            .compact();
        }

        u.setHash(hash);
        return ResponseEntity.ok(u);

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
