const formatTime = (seconds: number): string => {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainingSeconds = seconds % 60;

  const hoursString = hours > 0 ? `${hours}시간 ` : '';
  const minutesString = minutes > 0 ? `${minutes}분 ` : '';
  const secondsString = remainingSeconds > 0 ? `${remainingSeconds}초` : '';

  return `${hoursString}${minutesString}${secondsString}`;
};

export default formatTime;
