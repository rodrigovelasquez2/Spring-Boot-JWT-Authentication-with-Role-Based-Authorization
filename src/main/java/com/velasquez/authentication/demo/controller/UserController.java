package com.velasquez.authentication.demo.controller;

import com.velasquez.authentication.demo.entity.Users;
import com.velasquez.authentication.demo.service.UserServices;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controlador para gestión de usuarios.
 * Sigue el principio de Segregación de Interfaces (SOLID)
 */
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserServices userService;

    /**
     * Obtiene todos los usuarios (solo ADMIN)
     *
     * @return Lista de usuarios
     */
    @GetMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public List<Users> getAllUsers() {
        return userService.getAllUsers();
    }

    /**
     * Obtiene un usuario por ID
     *
     * @param id ID del usuario
     * @return Usuario encontrado
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public Users getUserById(@PathVariable Integer id) {
        return userService.getUserById(id);
    }

    /**
     * Crea un nuevo usuario (solo ADMIN)
     *
     * @param user Datos del usuario
     * @return Usuario creado
     */
    @PostMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public Users createUser(@RequestBody Users user) {
        return userService.createUser(user);
    }

    /**
     * Actualiza un usuario existente (solo ADMIN)
     */
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public Users updateUser(@PathVariable Integer id, @RequestBody Users users) {
        return userService.updateUser(id, users);
    }

    /**
     * Elimina un usuario (solo ADMIN)
     * @param id ID del usuario
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public void deleteUser(@PathVariable Integer id) {
        userService.deleteUser(id);
    }
}
