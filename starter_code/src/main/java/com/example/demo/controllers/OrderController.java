package com.example.demo.controllers;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.UserOrder;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.OrderRepository;
import com.example.demo.model.persistence.repositories.UserRepository;

@RestController
@RequestMapping("/api/order")
public class OrderController {
	private Logger log = LoggerFactory.getLogger(OrderController.class);

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private OrderRepository orderRepository;


	@PostMapping("/submit/{username}")
	public ResponseEntity<UserOrder> submit(@PathVariable String username) {
		User user = userRepository.findByUsername(username);
		if(user == null) {
			log.error("[SUBMIT ORDER] -> {FAIL} username "+username+" is not found in db.");
			return ResponseEntity.notFound().build();
		}
		//抓到目前的cart: 有點像是紀錄下訂單的紀錄
		UserOrder order = UserOrder.createFromCart(user.getCart());
		orderRepository.save(order);
		log.info("[SUBMIT ORDER] -> {SUCCESS} save a new submitted order from user -> "+order.getUser().getUsername());
		return ResponseEntity.ok(order);
	}

	//如果你想要看某個人的歷史紀錄
	@GetMapping("/history/{username}")
	public ResponseEntity<List<UserOrder>> getOrdersForUser(@PathVariable String username) {
		//先查看有沒有這個人
		User user = userRepository.findByUsername(username);
		if(user == null) {
			log.error("[GET HISTORY BY USERNAME] -> {FAIL} username "+username +" cannot find from db.");
			return ResponseEntity.notFound().build();
		}
		log.info("[GET HISTORY BY USERNAME] -> {SUCCESS} display the history from "+ user.getUsername());
		return ResponseEntity.ok(orderRepository.findByUser(user));
	}
}