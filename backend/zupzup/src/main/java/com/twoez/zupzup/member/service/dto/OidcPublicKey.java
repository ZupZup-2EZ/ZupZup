package com.twoez.zupzup.member.service.dto;

public record OidcPublicKey(String kid, String alg, String kty, String use, String n, String e) {}
