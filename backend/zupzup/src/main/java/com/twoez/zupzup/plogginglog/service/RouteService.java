package com.twoez.zupzup.plogginglog.service;


import com.twoez.zupzup.global.exception.flogginglog.RouteNotFoundException;
import com.twoez.zupzup.plogginglog.controller.dto.request.RouteAddRequest;
import com.twoez.zupzup.plogginglog.domain.Route;
import com.twoez.zupzup.plogginglog.repository.mongo.RouteRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class RouteService {

    private final RouteRepository routeRepository;

    @Transactional
    public void addRoute(RouteAddRequest request, Long ploggingLogId) {
        routeRepository.save(request.toDocument(ploggingLogId));
    }

    public Route searchRoute(Long id) {
        return routeRepository.findById(id).orElseThrow(RouteNotFoundException::new);
    }
}
