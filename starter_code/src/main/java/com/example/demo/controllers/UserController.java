package com.example.demo.controllers;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import com.example.demo.model.requests.CreateUserRequest;

@RestController
@RequestMapping("/api/user")
public class UserController {
	private static Logger log = LoggerFactory.getLogger(UserController.class);

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private CartRepository cartRepository;

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@GetMapping("/id/{id}")
	public ResponseEntity<User> findById(@PathVariable Long id) {
		log.info("[GET USER BY ID] -> id with ->" + id);
		return ResponseEntity.of(userRepository.findById(id));
	}

	@GetMapping("/{username}")
	public ResponseEntity<User> findByUserName(@PathVariable String username) {
		log.info("[GET USER BY USERNAME] -> username with ->" + username);
		User user = userRepository.findByUsername(username);
		return user == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(user);
	}

	@PostMapping("/create")
	public ResponseEntity<User> createUser(@RequestBody CreateUserRequest createUserRequest) {
		//創建User: 填入名字
		User user = new User();
		user.setUsername(createUserRequest.getUsername());
//		log.info("User name set with={}", createUserRequest.getUsername());
		log.info("[CREATE USER] -> name set with ->" + createUserRequest.getUsername());

		//create a new cart and save it into the repository
		Cart cart = new Cart();
		cartRepository.save(cart);
		user.setCart(cart); //set the user property: cart
		log.debug("Set Cart into the user", user.getCart());
		log.info("[CREATE CART] -> get id from cart ->" + cart.getId());

		//here to set bcrypt password
		if(createUserRequest.getPassword().length() < 7 ||
				!createUserRequest.getPassword().equals(createUserRequest.getConfirmPassword())){
			log.error("[CREATE USER] -> {FAIL} Error with user: " + user.getUsername() +", REASON -> password not matching");
			return ResponseEntity.badRequest().build();
		}
		//save the encoded password
		user.setPassword(bCryptPasswordEncoder.encode(createUserRequest.getPassword()));

		//then save the user
		userRepository.save(user);
		log.info("[CREATE USER] -> {SUCCESS} Save username: " + user.getUsername());

		return ResponseEntity.ok(user);
	}

}