package com.tfg.infractory;

import org.springframework.test.context.ActiveProfiles; // Add this import statement

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(classes = InfractoryApplication.class) // Specify your main application class
@ActiveProfiles("test")
class InfractoryApplicationTests {

	@Test
	void contextLoads() {
	}

}