package com.Games.LojaGames.controller;

import com.Games.LojaGames.security.JWTUtil;
import com.Games.LojaGames.dto.UsuarioLoginDTO;
import com.Games.LojaGames.dto.UsuarioRegistroDTO;
import com.Games.LojaGames.model.Usuario;
import com.Games.LojaGames.repository.UsuarioRepository;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UsuarioRepository repository;

    @Autowired
    private JWTUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody UsuarioLoginDTO data) {

        var usernamePassword =
                new UsernamePasswordAuthenticationToken(
                        data.nomeUsuario(),
                        data.senha()
                );

        var auth = this.authenticationManager.authenticate(usernamePassword);

        Usuario usuario = (Usuario) auth.getPrincipal();

        String token = jwtUtil.gerarToken(usuario);

        return ResponseEntity.ok(
                Map.of(
                        "nomeUsuario", usuario.getNomeUsuario(),
                        "token", token
                )
        );
    }

    @PostMapping("/registrar")
    public ResponseEntity registrar(@RequestBody UsuarioRegistroDTO data) {

        if (data.nomeUsuario() == null) {
            return ResponseEntity.badRequest().build();
        }

        if (this.repository.findByNomeUsuario(data.nomeUsuario()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }

        String encryptedPassword =
                new BCryptPasswordEncoder().encode(data.senha());

        Usuario novoUsuario = new Usuario();

        novoUsuario.setNomeUsuario(data.nomeUsuario());
        novoUsuario.setEmail(data.email());
        novoUsuario.setSenha(encryptedPassword);
        novoUsuario.setNomeCompleto(data.nomeCompleto());

        this.repository.save(novoUsuario);

        return ResponseEntity.ok().build();
    }
}