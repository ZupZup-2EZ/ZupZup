import styled from 'styled-components';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ConfirmButton,
  OnBoardingFirst,
  OnBoardingSecond,
  OnBoardingThird,
} from 'components';
import { URL } from 'utils';

import ArrowSvg from 'assets/icons/angle-right.svg?react';

const RegistSuccess = () => {
  const navigate = useNavigate();
  const [tab, setTab] = useState<number>(1);
  const tabContent = [
    <OnBoardingFirst />,
    <OnBoardingSecond />,
    <OnBoardingThird />,
  ];

  const handleFinishTutorial = () => {
    alert('튜토리얼은 마이페이지 > 설정에서 다시 확인할 수 있어요!');
    navigate(URL.PLOGGING.LOBBY);
  };

  const handleNextButton = () => {
    setTab(tab + 1);
  };

  const handlePrevButton = () => {
    setTab(tab - 1);
  };

  return (
    <S.Wrap>
      <S.Bar>
        {[...new Array(3)].map((_, i) => (
          <S.BarSegment active={tab === i + 1} onClick={() => setTab(i + 1)} />
        ))}
      </S.Bar>
      <S.TopFrame onClick={handleFinishTutorial}>
        Skip <ArrowSvg />
      </S.TopFrame>

      {tabContent[tab - 1]}

      <S.BottomFrame>
        {tab !== 1 && (
          <ConfirmButton
            text="이전"
            onClick={handlePrevButton}
            color="#a0a0a0ad"
          />
        )}
        <ConfirmButton
          text={tab === 3 ? '시작하기' : '다음'}
          onClick={() =>
            tab === 3 ? handleFinishTutorial() : handleNextButton()
          }
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

  TopFrame: styled.div`
    cursor: pointer;
    width: fit-content;
    display: flex;
    align-items: flex-end;
    gap: 2px;
    margin: 30px 10px 0;
    align-self: flex-end;
    font-family: ${({ theme }) => theme.font.family.focus1};
    font-size: ${({ theme }) => theme.font.size.focus3};
    color: ${({ theme }) => theme.color.gray2};
  `,

  Bar: styled.div`
    width: 100%;
    display: flex;
    gap: 2px;
    margin-top: 10px;
  `,

  BarSegment: styled.div<{ active: boolean }>`
    width: 33.3%;
    height: 5px;
    background-color: ${props =>
      props.active ? props.theme.color.main : props.theme.color.gray4};
    border-radius: 4px;
    cursor: pointer;
  `,
  BottomFrame: styled.div`
    display: flex;
    flex-direction: column;
    align-items: center;
    bottom: 0;
    width: 100%;
    margin: auto 0 50px 0;

    & div {
      margin-top: 10px;
    }
  `,
};
export default RegistSuccess;
