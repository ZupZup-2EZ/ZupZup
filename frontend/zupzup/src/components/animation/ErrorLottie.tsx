import Lottie from 'lottie-react';
import errorLottie from 'assets/lottie/404-lottie.json';

import { LottieFrame } from './LottieStyle';

const ErrorAnimation = () => {
  return (
    <LottieFrame>
      <Lottie
        className="lottie"
        animationData={errorLottie}
        height={200}
        width={200}
      />
    </LottieFrame>
  );
};

export default ErrorAnimation;
