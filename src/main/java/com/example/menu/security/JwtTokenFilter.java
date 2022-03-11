package com.example.menu.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;

public class JwtTokenFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String token = resolveToken(httpServletRequest);
        try {
            Authentication authentication = new IssuerValidator();
            authentication.setAuthenticated(true);
            if (token != null) {
                String[] chunks = token.split("\\.");
                Base64.Decoder decoder = Base64.getUrlDecoder();

                String header = new String(decoder.decode(chunks[0]));
                String payload = new String(decoder.decode(chunks[1]));

                ObjectMapper objectMapper = new ObjectMapper();
                Map headerMap = objectMapper.readValue(header, Map.class);
                Map payloadMap = objectMapper.readValue(payload, Map.class);

                String aud = payloadMap.get("aud").toString();

                if (!aud.equalsIgnoreCase("https://menu-api.example.com")) {
                    httpServletResponse.sendError(HttpStatus.UNAUTHORIZED.value(), "Unauthorized");
                }
            } else {
                httpServletResponse.sendError(HttpStatus.UNAUTHORIZED.value(), "Unauthorized");
            }
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (CustomException ex) {
            SecurityContextHolder.clearContext();
            httpServletResponse.sendError(HttpStatus.UNAUTHORIZED.value(), ex.getMessage());
            return;
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    public String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
