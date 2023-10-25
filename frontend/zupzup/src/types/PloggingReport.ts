export interface PloggingReport {
  image: string;
  record: RecordInfo;
}

export interface RecordInfo {
  time: number;
  coin: number;
  distance: number;
  calories: number;
}
