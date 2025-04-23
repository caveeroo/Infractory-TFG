package com.tfg.infractory.web.controller;

import java.util.List;
import org.slf4j.Logger;
import java.util.ArrayList;
import org.slf4j.LoggerFactory;
import org.springframework.ui.Model;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import com.tfg.infractory.infrastructure.secrets.model.Secret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import com.tfg.infractory.infrastructure.secrets.service.SecretsService;

@Controller
@RequestMapping("/secrets")
public class SecretsController {

    @Autowired
    private SecretsService secretsService;

    private static final Logger logger = LoggerFactory.getLogger(SecretsController.class);

    @GetMapping
    public String viewSecrets(Model model) {
        List<Secret> allSecrets = secretsService.getAllSecrets();
        List<Secret> userSecrets = new ArrayList<>();
        List<Secret> nebulaSecrets = new ArrayList<>();

        for (Secret secret : allSecrets) {
            if (secret.getType().startsWith("NEBULA_")) {
                nebulaSecrets.add(secret);
            } else {
                userSecrets.add(secret);
            }
        }

        model.addAttribute("userSecrets", userSecrets);

        // no need for the user to see nebula secrets
        model.addAttribute("nebulaSecrets", nebulaSecrets);
        return "secrets/index";
    }

    @PostMapping("/create")
    public String createSecret(@RequestParam("name") String name,
            @RequestParam("type") String type,
            @RequestParam("content") String content,
            RedirectAttributes redirectAttributes) {
        try {
            secretsService.addSecret(name, type, content);
            redirectAttributes.addFlashAttribute("successMessage", "Secret added successfully");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Failed to add secret: " + e.getMessage());
        }
        return "redirect:/secrets";
    }

    @PostMapping("/{id}/delete")
    public String deleteSecret(@PathVariable("id") Long id, RedirectAttributes redirectAttributes) {
        logger.info("Attempting to delete secret with id: {}", id);
        try {
            secretsService.deleteSecret(id);
            redirectAttributes.addFlashAttribute("successMessage", "Secret deleted successfully");
            logger.info("Secret with id {} deleted successfully", id);
        } catch (Exception e) {
            logger.error("Failed to delete secret with id {}: {}", id, e.getMessage());
            redirectAttributes.addFlashAttribute("errorMessage", "Failed to delete secret: " + e.getMessage());
        }
        return "redirect:/secrets";
    }
}