package com.twoez.zupzup.support.docs;

import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.twoez.zupzup.config.security.filter.JwtAuthenticationFilter;
import com.twoez.zupzup.support.security.MockSecurityFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.restdocs.RestDocumentationContextProvider;
import org.springframework.restdocs.RestDocumentationExtension;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.filter.CharacterEncodingFilter;

@ExtendWith({RestDocumentationExtension.class, SpringExtension.class})
@Import(RestDocsConfiguration.class)
@AutoConfigureRestDocs
@ActiveProfiles("test")
@WebMvcTest
public class RestDocsTest {

    @Autowired private ObjectMapper objectMapper;
    protected MockMvc mockMvc;

    @MockBean private JwtAuthenticationFilter jwtAuthenticationFilter;

    protected String toJson(Object value) throws JsonProcessingException {
        return objectMapper.writeValueAsString(value);
    }

    @BeforeEach
    public void setMockMvc(
            WebApplicationContext context, RestDocumentationContextProvider provider) {
        mockMvc =
                MockMvcBuilders.webAppContextSetup(context)
                        .apply(
                                documentationConfiguration(provider)
                                        .uris()
                                        .withScheme("http")
                                        .withHost("k9a202.p.ssafy.io")
                                        .withPort(8080))
                        .apply(springSecurity(new MockSecurityFilter()))
                        .addFilter(new CharacterEncodingFilter("UTF-8", true))
                        .alwaysDo(print())
                        .alwaysDo(document("api/v1"))
                        .build();
    }
}
