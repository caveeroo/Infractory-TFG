package com.tfg.infractory.web.controller;

import com.tfg.infractory.infrastructure.ssh.service.SSHKeyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Controller
@RequestMapping("/ssh-keys")
public class SSHKeyController {

    @Autowired
    private SSHKeyService sshKeyService;

    private static final Logger logger = LoggerFactory.getLogger(SSHKeyController.class);

    @GetMapping
    public String viewSSHKeys(Model model) {
        model.addAttribute("sshKeys", sshKeyService.getAllSSHKeys());
        return "ssh-keys/index";
    }

    @PostMapping("/create")
    public String createSSHKey(@RequestParam("name") String name,
            @RequestParam("publicKey") String publicKey,
            @RequestParam("privateKey") String privateKey,
            RedirectAttributes redirectAttributes) {
        try {
            // Trim inputs
            name = name.trim();
            publicKey = publicKey.trim();
            privateKey = privateKey.trim();

            logger.debug("Received SSH key with name: {}, publicKey length: {}, privateKey length: {}",
                    name, publicKey.length(), privateKey.length());
            sshKeyService.addSSHKey(name, publicKey, privateKey);
            redirectAttributes.addFlashAttribute("successMessage", "SSH key added successfully");
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Failed to add SSH key: " + e.getMessage());
            logger.error("Failed to add SSH key: {}", e.getMessage());
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage",
                    "An unexpected error occurred while adding the SSH key");
            logger.error("Error adding SSH key", e);
        }
        return "redirect:/ssh-keys";
    }

    @PostMapping("/{id}/delete")
    public String deleteSSHKey(@PathVariable("id") Long id, RedirectAttributes redirectAttributes) {
        logger.info("Attempting to delete SSH key with id: {}", id);
        try {
            sshKeyService.deleteSSHKey(id);
            redirectAttributes.addFlashAttribute("successMessage", "SSH key deleted successfully");
            logger.info("SSH key with id {} deleted successfully", id);
        } catch (Exception e) {
            logger.error("Failed to delete SSH key with id {}: {}", id, e.getMessage());
            redirectAttributes.addFlashAttribute("errorMessage", "Failed to delete SSH key: " + e.getMessage());
        }
        return "redirect:/ssh-keys";
    }
}