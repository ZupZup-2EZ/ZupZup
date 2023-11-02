import styled, { keyframes } from 'styled-components';

import { useCountdownTimer } from 'hooks';
import * as utils from 'utils';

const OnBoarding = () => {
  useCountdownTimer(3, utils.URL.LOGIN.HOME);

  return (
    <S.Wrap>
      <S.Title>줍줍</S.Title>
      <S.Background src="assets/images/park_main.png" />
    </S.Wrap>
  );
};

export default OnBoarding;

const FadeIn = keyframes`
  0% {
    opacity: 0;
  }
  100% {
    opacity: 1;
  }
`;

const S = {
  Wrap: styled.div`
    display: flex;
    flex-direction: column;
    overflow: hidden;
    width: 100%;
    height: 100vh;
    background: linear-gradient(
      180deg,
      #fff 0%,
      #fff 0.01%,
      #fff 14.69%,
      #b8f2e8 48.54%,
      #2cd5fb 99.41%
    );
  `,
  Title: styled.div`
    margin-top: 200px;
    transform: translateY(150px);
    text-align: center;
    font-family: ${({ theme }) => theme.font.family.title};
    font-size: ${({ theme }) => theme.font.size.title};
    color: ${({ theme }) => theme.color.white};
    text-shadow: 0px 4px 4px rgba(0, 0, 0, 0.3);
    z-index: 1;
    animation: ${FadeIn} 2s;
  `,

  Background: styled.img`
    animation: ${FadeIn} 2s;
  `,
};
