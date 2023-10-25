import { useRef, useEffect } from 'react';
import styled from 'styled-components';

import { useGeolocation } from 'hooks';

interface Location {
  lat: number;
  lng: number;
}

const PloggingMap = () => {
  const location = useGeolocation();
  const mapRef = useRef(null);

  const initMap = (location: Location) => {
    const { Tmapv3 } = window;
    const map = new Tmapv3.Map(mapRef.current!, {
      center: new Tmapv3.LatLng(location.lat, location.lng),
      width: '100%',
      height: '100%',
      zoom: 17,
    });

    new Tmapv3.Marker({
      position: new Tmapv3.LatLng(location.lat, location.lng),
      map: map,
    });
  };

  const initPosition = (): Location => {
    let position: Location = {
      lat: 37.5013068,
      lng: 127.0396597,
    };
    if (location.loaded) {
      position = {
        lat: location.coordinates!.lat,
        lng: location.coordinates!.lng,
      };
    }

    return position;
  };

  useEffect(() => {
    if (!(mapRef.current! as HTMLElement).firstChild) {
      initMap(initPosition());
    }
  }, []);

  return (
    <S.Wrap>
      <S.Map ref={mapRef}></S.Map>
    </S.Wrap>
  );
};

export default PloggingMap;

const S = {
  Wrap: styled.div`
    width: 100%;
    height: 100%;
  `,
  Map: styled.div`
    width: 100%;
    height: 100%;
  `,
};
