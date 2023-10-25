import Lottie from 'lottie-react';
import loadingLottie from 'assets/lottie/loading-lottie.json';

import { LottieFrame } from './LottieStyle';

const LoadingAnimation = () => {
  return (
    <LottieFrame>
      <Lottie
        className="lottie"
        animationData={loadingLottie}
        height={200}
        width={200}
      />
    </LottieFrame>
  );
};

export default LoadingAnimation;
