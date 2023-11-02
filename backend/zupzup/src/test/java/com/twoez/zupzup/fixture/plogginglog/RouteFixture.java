package com.twoez.zupzup.fixture.plogginglog;


import com.twoez.zupzup.plogginglog.controller.dto.request.RouteAddRequest;
import com.twoez.zupzup.plogginglog.domain.Location;
import com.twoez.zupzup.plogginglog.domain.Route;
import java.math.BigDecimal;
import java.util.List;
import java.util.stream.IntStream;

public enum RouteFixture {
    DEFAULT(
            1L,
            IntStream.range(0, 10)
                    .mapToObj(
                            idx ->
                                    Location.of(
                                            BigDecimal.valueOf(idx), BigDecimal.valueOf(idx + 1)))
                    .toList());
    private Long id;
    private List<Location> locations;

    RouteFixture(Long id, List<Location> locations) {
        this.id = id;
        this.locations = locations;
    }

    public Route getRoute() {
        return new Route(id, locations);
    }

    public RouteAddRequest getRouteAddRequest() {
        return new RouteAddRequest(locations);
    }
}
