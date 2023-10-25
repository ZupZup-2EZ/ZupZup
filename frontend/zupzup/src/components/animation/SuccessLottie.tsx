import Lottie from 'lottie-react';
import successLottie from 'assets/lottie/success-lottie.json';

import { LottieFrame } from './LottieStyle';

const SuccessAnimation = () => {
  return (
    <LottieFrame width={70} height={70}>
      <Lottie
        className="lottie"
        loop={false}
        animationData={successLottie}
        height={200}
        width={200}
      />
    </LottieFrame>
  );
};

export default SuccessAnimation;
