import styled from 'styled-components';
import { SuccessAnimation } from 'components';
import useCountdownTimer from 'hooks/useCountdownTimer';
import * as utils from 'utils';

const PloggingDone = () => {
  const time = useCountdownTimer(3, utils.URL.PLOGGING.REPORT);
  return (
    <S.Wrap>
      <S.TitleFrame>
        <S.MainTitle>
          오늘도 줍줍님 덕분에
          <br />
          길이 깨끗해졌어요!
        </S.MainTitle>
        <S.SubTitle>획득한 코인을 가지고 캐릭터를 성장시켜주세요</S.SubTitle>
      </S.TitleFrame>
      <SuccessAnimation />
      <S.BottomFrame>
        <S.BottomText>{time}초 후 결과 화면으로 이동합니다</S.BottomText>
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
  TitleFrame: styled.div`
    margin-top: 75px;
  `,
  MainTitle: styled.div`
    font-size: ${({ theme }) => theme.font.size.display1};
    font-family: ${({ theme }) => theme.font.family.display1};
    font-weight: ${({ theme }) => theme.font.weight.body2};
    display: flex;
    align-items: center;
    justify-content: center;
    text-align: center;
    line-height: 35px;
  `,
  SubTitle: styled.div`
    margin-top: 10px;
    color: ${({ theme }) => theme.color.gray2};
    font-size: ${({ theme }) => theme.font.size.body2};
    font-family: ${({ theme }) => theme.font.family.body2};
    font-weight: ${({ theme }) => theme.font.weight.body2};
    line-height: ${({ theme }) => theme.font.lineheight.body2};
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
export default PloggingDone;
