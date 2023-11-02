package com.twoez.zupzup.plogginglog.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.times;

import com.twoez.zupzup.fixture.plogginglog.RouteFixture;
import com.twoez.zupzup.global.exception.flogginglog.RouteNotFoundException;
import com.twoez.zupzup.plogginglog.controller.dto.request.RouteAddRequest;
import com.twoez.zupzup.plogginglog.domain.Location;
import com.twoez.zupzup.plogginglog.domain.Route;
import com.twoez.zupzup.plogginglog.repository.mongo.RouteRepository;
import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class RouteServiceTest {

    @Mock RouteRepository routeRepository;
    @InjectMocks RouteService routeService;

    @Test
    @DisplayName("플로깅 이동경로를 저장한다.")
    void addRouteTest() {
        RouteAddRequest request =
                new RouteAddRequest(
                        List.of(
                                Location.of(
                                        BigDecimal.valueOf(36.341423),
                                        BigDecimal.valueOf(127.43531))));
        Route route = RouteFixture.DEFAULT.getRoute();
        given(routeRepository.save(any(Route.class))).willReturn(route);

        routeService.addRoute(request, 1L);

        then(routeRepository).should(times(1))
                .save(any(Route.class));
    }

    @Test
    @DisplayName("플로깅 이동경로를 조회한다.")
    void searchRouteTest() {
        Route route = RouteFixture.DEFAULT.getRoute();
        given(routeRepository.findById(any(Long.class))).willReturn(Optional.of(route));

        Route result = routeService.searchRoute(1L);

        assertThat(result).isEqualTo(route);
    }

    @Test
    @DisplayName("조회 가능한 플로깅 이동경로가 없을 경우 예외를 발생시킨다")
    void searchRouteFailTest() {
        given(routeRepository.findById(any(Long.class))).willReturn(Optional.empty());

        assertThatThrownBy(() -> routeService.searchRoute(1L))
                .isInstanceOf(RouteNotFoundException.class);
    }
}
