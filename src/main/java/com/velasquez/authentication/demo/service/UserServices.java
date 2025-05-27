package com.velasquez.authentication.demo.service;

import com.velasquez.authentication.demo.entity.Role;
import com.velasquez.authentication.demo.entity.Users;
import com.velasquez.authentication.demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
@Service
@RequiredArgsConstructor
public class UserServices {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Obtiene todos los usuarios
     * @return Lista de usuarios
     */
    public List<Users> getAllUsers() {
        return userRepository.findAll();
    }

    /**
     * Obtiene un usuario por ID
     * @param id ID del usuario
     * @return Usuario encontrado
     * @throws RuntimeException si el usuario no existe
     */
    public Users getUserById(Integer id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    /**
     * Crea un nuevo usuario
     * @param user Datos del usuario
     * @return Usuario creado
     */
    public Users createUser(Users user) {
        // Validar que el email no esté ya registrado
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            throw new RuntimeException("Ya existe un usuario con este email: " + user.getEmail());
        }

        // Asignar rol por defecto si es null
        if (user.getRole() == null) {
            user.setRole(Role.ROLE_USER);
        }

        // Encriptar la contraseña
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    /**
     * Actualiza un usuario existente
     * @param id ID del usuario
     * @param userDetails Datos actualizados
     * @return Usuario actualizado
     * @throws RuntimeException si el usuario no existe
     */
    public Users updateUser(Integer id, Users userDetails) {
        Users user = getUserById(id);
        user.setFirstName(userDetails.getFirstName());
        user.setLastName(userDetails.getLastName());
        user.setEmail(userDetails.getEmail());
        if (userDetails.getPassword() != null) {
            user.setPassword(passwordEncoder.encode(userDetails.getPassword()));
        }
        user.setRole(userDetails.getRole());
        return userRepository.save(user);
    }

    /**
     * Elimina un usuario
     * @param id ID del usuario
     */
    public void deleteUser(Integer id) {
        userRepository.deleteById(id);
    }
}
