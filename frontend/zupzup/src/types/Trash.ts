export interface TrashReport {
  image: string;
  coin: CoinInfo[];
  totalCoin: number;
}

export interface CoinInfo {
  name: string;
  value: number;
}
