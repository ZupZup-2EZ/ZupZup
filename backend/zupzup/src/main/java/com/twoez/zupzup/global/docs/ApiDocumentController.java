package com.twoez.zupzup.global.docs;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/v1/docs")
public class ApiDocumentController {

    @GetMapping("/api")
    public String getDocs() {
        return "index";
    }
}
