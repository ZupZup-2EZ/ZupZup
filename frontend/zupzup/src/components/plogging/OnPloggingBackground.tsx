import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import styled from 'styled-components';

import * as utils from 'utils';

import SmallRunnerSvg from 'assets/icons/smallrunner.svg?react';
import CoinSvg from 'assets/icons/coin.svg?react';
import TrashCanSvg from 'assets/icons/trash_can.svg?react';
import CancelTrashCanSvg from 'assets/icons/cancel_trash_can.svg?react';
import CameraSvg from 'assets/icons/camera.svg?react';
import RefreshSvg from 'assets/icons/refresh.svg?react';

interface trashButtonProps {
  trashOn: boolean;
}

const OnPloggingBackground = () => {
  const navigate = useNavigate();

  const [trashOn, setTrashOn] = useState<boolean>(false);

  return (
    <S.Wrap>
      <S.CurrentState>
        <S.CurrentCoin>
          <CoinSvg />
          15
        </S.CurrentCoin>
        <S.ExitButton>
          <SmallRunnerSvg /> 종료하기
        </S.ExitButton>
      </S.CurrentState>
      <S.TrashToggleBox>
        <S.RefreshButton trashOn={trashOn}>
          <RefreshSvg />
        </S.RefreshButton>
      </S.TrashToggleBox>
      <S.UserAccess>
        <S.CameraButton onClick={() => navigate(utils.URL.PLOGGING.CAMERA)}>
          <CameraSvg />
        </S.CameraButton>
        <S.PloggingInfoButton>
          <SmallRunnerSvg /> 플로깅 정보 확인
        </S.PloggingInfoButton>
        <S.TrashButton onClick={() => setTrashOn(!trashOn)} trashOn={trashOn}>
          {trashOn ? <TrashCanSvg /> : <CancelTrashCanSvg />}
        </S.TrashButton>
      </S.UserAccess>
    </S.Wrap>
  );
};

export default OnPloggingBackground;

const S = {
  Wrap: styled.div`
    display: flex;
    flex-direction: column;
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: linear-gradient(
      180deg,
      #f5f4f8 0%,
      rgba(255, 255, 255, 0.65) 20.02%,
      rgba(255, 255, 255, 0) 35.13%,
      rgba(255, 255, 255, 0) 100%
    );

    filter: drop-shadow(0px 20px 20px rgba(112, 112, 112, 0.1));
    box-shadow: 0px 20px 20px 0px rgba(112, 112, 112, 0.1);
    z-index: 99;
    pointer-events: none;
  `,
  CurrentState: styled.div`
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 100%;
    height: 94px;
    padding: 0 30px;
  `,
  CurrentCoin: styled.div`
    display: flex;
    align-items: center;
    font-size: ${({ theme }) => theme.font.size.display3};
    font-family: ${({ theme }) => theme.font.family.display3};
    line-height: ${({ theme }) => theme.font.lineheight.display3};
    color: ${({ theme }) => theme.color.gray2};

    & > svg {
      margin: 2px;
    }
  `,
  ExitButton: styled.button`
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 110px;
    height: 34px;
    border-radius: 4px;
    color: ${({ theme }) => theme.color.white};
    background-color: ${({ theme }) => theme.color.main};
    font-size: ${({ theme }) => theme.font.size.focus2};
    font-family: ${({ theme }) => theme.font.family.focus2};
    line-height: ${({ theme }) => theme.font.lineheight.focus2};
    padding: 6px 10px;
    pointer-events: auto;

    &:hover {
      background-color: ${({ theme }) => theme.color.sub};
    }
  `,
  UserAccess: styled.div`
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin: 20px 0 56px;
    padding: 0 28px;
  `,
  CameraButton: styled.button`
    display: flex;
    align-items: center;
    justify-content: center;
    width: 58px;
    height: 58px;
    border-radius: 29px;
    background-color: ${({ theme }) => theme.color.main};
    color: ${({ theme }) => theme.color.white};
    pointer-events: auto;

    &:hover {
      background-color: ${({ theme }) => theme.color.sub};
    }
  `,
  PloggingInfoButton: styled.button`
    display: flex;
    align-items: center;
    justify-content: center;
    width: 160px;
    height: 34px;
    border-radius: 4px;
    background-color: ${({ theme }) => theme.color.main};
    color: ${({ theme }) => theme.color.white};
    font-size: ${({ theme }) => theme.font.size.focus2};
    font-family: ${({ theme }) => theme.font.family.focus2};
    line-height: ${({ theme }) => theme.font.lineheight.focus2};
    pointer-events: auto;

    & > svg {
      margin: 0 6px 0 0;
    }

    &:hover {
      background-color: ${({ theme }) => theme.color.sub};
    }
  `,
  TrashToggleBox: styled.div`
    display: flex;
    justify-content: flex-end;
    width: 100%;
    height: 56px;
    margin: auto 0 0 0;
    padding: 0 30px;
  `,
  RefreshButton: styled.button<trashButtonProps>`
    display: ${({ trashOn }) => (trashOn ? 'flex' : 'none')};
    align-items: center;
    justify-content: center;
    width: 58px;
    height: 58px;
    border-radius: 29px;
    background-color: ${({ theme }) => theme.color.sub2};
    color: ${({ theme }) => theme.color.white};
    pointer-events: auto;

    &:hover {
      background-color: ${({ theme }) => theme.color.sub};
    }
  `,
  TrashButton: styled.button<trashButtonProps>`
    display: flex;
    align-items: center;
    justify-content: center;
    width: 58px;
    height: 58px;
    border-radius: 29px;
    background-color: ${({ trashOn, theme }) =>
      trashOn ? theme.color.main : theme.color.gray3};
    color: ${({ theme }) => theme.color.white};
    pointer-events: auto;

    &:hover {
      background-color: ${({ trashOn, theme }) =>
        trashOn ? theme.color.sub : ''};
    }
  `,
};
