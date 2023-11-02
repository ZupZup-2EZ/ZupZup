import styled from 'styled-components';
import { useNavigate } from 'react-router-dom';
import * as utils from 'utils';
import ArrowSvg from 'assets/icons/angle-right.svg?react';

import { SuccessAnimation, ConfirmButton } from 'components';

const RegistSuccess = () => {
  const navigate = useNavigate();

  return (
    <S.Wrap>
      <S.TitleFrame>
        <S.MainTitle>가입이 완료 되었어요</S.MainTitle>
        <S.SubTitle>즐거운 줍줍 기록을 시작해요 🎉</S.SubTitle>
      </S.TitleFrame>
      <SuccessAnimation />
      <S.BottomFrame>
        <div
          className="skip"
          onClick={() => navigate(utils.URL.PLOGGING.LOBBY)}
        >
          건너뛸게요
          <ArrowSvg />
        </div>
        <ConfirmButton
          text="튜토리얼 보러가기"
          onClick={() => navigate(utils.URL.ONBORDING.EXPLAIN)}
        />
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
    text-align: center;
  `,
  MainTitle: styled.div`
    font-size: ${({ theme }) => theme.font.size.display1};
    font-family: ${({ theme }) => theme.font.family.display1};
    font-weight: ${({ theme }) => theme.font.weight.body2};
    line-height: ${({ theme }) => theme.font.lineheight.display1};
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
    bottom: 0;
    width: 100%;
    margin: auto 0 50px 0;

    & div {
      cursor: pointer;
      margin-top: 20px;
      font-family: ${({ theme }) => theme.font.family.focus2};
      font-size: ${({ theme }) => theme.font.size.focus2};
    }

    & .skip {
      display: flex;
      align-items: center;
      color: ${({ theme }) => theme.color.gray2};
      gap: 3px;
    }
  `,
};
export default RegistSuccess;
