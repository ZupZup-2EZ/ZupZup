interface Map {
  map: object;
}

interface LatLng {
  latLng: object;
}

interface TmapOptions {
  center: object;
  width: string;
  height: string;
  zoom: number;
}

interface MapLocation {
  lat: number;
  lng: number;
}

interface MarkerOptions {
  position: LatLng;
  map: Map;
}

export declare global {
  interface Window {
    Tmapv3: {
      Map: {
        new (container: HTMLElement, options: TmapOptions): Map;
      };
      LatLng: {
        new (lat: number, lon: number): LatLng;
      };
      Marker: {
        new (options: MarkerOptions): object;
      };
    };
  }
}
