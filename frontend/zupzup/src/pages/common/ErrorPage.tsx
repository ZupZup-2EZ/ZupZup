import styled from 'styled-components';
import { ErrorAnimation } from 'components';
import useCountdownTimer from 'hooks/useCountdownTimer';
import * as utils from 'utils';

const ErrorPage = () => {
  const time = useCountdownTimer(3, utils.URL.PLOGGING.LOBBY);

  return (
    <S.Wrap>
      <ErrorAnimation />
      <S.BottomFrame>
        <S.BottomText>{time}초 후 메인화면으로 이동합니다</S.BottomText>
      </S.BottomFrame>
    </S.Wrap>
  );
};

const S = {
  Wrap: styled.div`
    display: flex;
    flex-direction: column;
    align-items: center;
    overflow: hidden;
    width: 100%;
    height: 100vh;
    background-color: ${({ theme }) => theme.color.background};
  `,
  BottomFrame: styled.div`
    display: flex;
    flex-direction: column;
    align-items: center;
    position: absolute;
    bottom: 0;
    width: 100%;
    margin-bottom: 35px;
  `,
  BottomText: styled.div`
    font-size: ${({ theme }) => theme.font.size.body3};
    font-family: ${({ theme }) => theme.font.family.body3};
    font-weight: ${({ theme }) => theme.font.weight.body3};
    line-height: ${({ theme }) => theme.font.lineheight.body3};
  `,
};
export default ErrorPage;
