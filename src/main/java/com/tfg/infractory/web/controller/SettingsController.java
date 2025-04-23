package com.tfg.infractory.web.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.ui.Model;

@Controller
@RequestMapping("/settings")
public class SettingsController {
    @GetMapping
    public String viewSettings(Model model) {
        // Add logic to populate the model with settings data
        return "settings/index"; // Return the view name for settings
    }
}