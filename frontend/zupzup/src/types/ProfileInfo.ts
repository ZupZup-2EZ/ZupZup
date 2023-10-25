export interface ProfileInfo {
  nickname: string;
  characterImage: string;
  day: number;
  level: number;
  exp: number;
  lastPlogging: LastPloggingInfo;
}

export interface LastPloggingInfo {
  count: number;
  hour: number;
  calories: number;
}
