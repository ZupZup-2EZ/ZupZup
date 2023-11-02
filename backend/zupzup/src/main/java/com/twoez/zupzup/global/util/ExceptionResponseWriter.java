package com.twoez.zupzup.global.util;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.twoez.zupzup.global.response.ApiResponse;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

public class ExceptionResponseWriter<T> {

    public static <T> void writeException(
            HttpServletResponse response, HttpStatus httpStatus, T errorResponse)
            throws IOException {
        response.setStatus(httpStatus.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        PrintWriter writer = response.getWriter();
        ObjectMapper mapper = new ObjectMapper();
        writer.write(mapper.writeValueAsString(ApiResponse.status(httpStatus).body(errorResponse)));
        writer.flush();
    }
}
