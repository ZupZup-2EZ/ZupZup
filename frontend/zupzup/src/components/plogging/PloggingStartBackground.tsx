import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import styled from 'styled-components';

import { format } from 'date-fns';
import { RecentRecord, ConfirmButton } from 'components';
import * as utils from 'utils';
import { PloggingApis } from 'api';
import { useAppDispatch } from 'hooks';
import { setPloggingId, setStartDateTime } from 'hooks/store/usePlogging';

const PloggingStartBackground = () => {
  const navigate = useNavigate();
  const dispatch = useAppDispatch();
  const [nowPloggingUser, setNowPloggingUser] = useState<number>(0);

  const fetchNowPloggingUser = async () => {
    try {
      const response = await PloggingApis.getNowPloggingUsers();
      const data = response.data.results.totalPlogger;
      setNowPloggingUser(data);
    } catch (e) {
      console.error(e);
    }
  };

  const handleStartPlogging = async () => {
    localStorage.removeItem(utils.COORDINATE.LOCATIONS_KEY);
    localStorage.removeItem(utils.COORDINATE.MIN_LATITUDE);
    localStorage.removeItem(utils.COORDINATE.MAX_LATITUDE);
    localStorage.removeItem(utils.COORDINATE.MIN_LONGITUDE);
    localStorage.removeItem(utils.COORDINATE.MAX_LONGITUDE);
    const response = await PloggingApis.startPlogging();
    dispatch(setPloggingId(response.data.results.ploggingLogId));
    dispatch(setStartDateTime(format(new Date(), "yyyy-MM-dd'T'HH:mm:ss")));
    navigate(utils.URL.PLOGGING.ON);
  };

  useEffect(() => {
    fetchNowPloggingUser();
  }, []);

  return (
    <S.Wrap>
      <RecentRecord />
      <S.Header>
        <S.SubTitle>
          {nowPloggingUser === 0 ? (
            <>첫 플로깅 유저가 되어보세요!</>
          ) : (
            <>
              현재 <S.CurrentMember>{nowPloggingUser}</S.CurrentMember> 명이
              플로깅 중이에요
            </>
          )}
        </S.SubTitle>
        <S.Title>지금 바로 플로깅을 시작해주세요!</S.Title>
      </S.Header>
      <ConfirmButton text="플로깅 시작하기" onClick={handleStartPlogging} />
    </S.Wrap>
  );
};

export default PloggingStartBackground;

const S = {
  Wrap: styled.div`
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: linear-gradient(
      180deg,
      #f5f4f8 0%,
      rgba(255, 255, 255, 0.65) 50.75%,
      rgba(255, 255, 255, 0) 100%
    );
    box-shadow: 0px 20px 20px 0px rgba(112, 112, 112, 0.1);
    z-index: 99;
    pointer-events: none;
  `,
  Header: styled.div`
    display: flex;
    flex-direction: column;
    align-items: center;
  `,
  SubTitle: styled.div`
    display: flex;
    font-size: ${({ theme }) => theme.font.size.display3};
    font-family: ${({ theme }) => theme.font.family.display3};
    line-height: ${({ theme }) => theme.font.lineheight.display3};
    margin: 32px 0 0 0;
  `,
  CurrentMember: styled.div`
    margin: 0 6px;
    color: ${({ theme }) => theme.color.main};
    font-size: ${({ theme }) => theme.font.size.display3};
    font-family: ${({ theme }) => theme.font.family.display3};
    line-height: ${({ theme }) => theme.font.lineheight.display3};
  `,
  Title: styled.div`
    font-size: ${({ theme }) => theme.font.size.display1};
    font-family: ${({ theme }) => theme.font.family.display1};
    line-height: ${({ theme }) => theme.font.lineheight.display1};
    margin: 11px 0 0 0;
  `,
  StartButton: styled.div`
    display: flex;
    justify-content: center;
    align-items: center;
    width: calc(100% - 56px);
    height: 52px;
    font-size: ${({ theme }) => theme.font.size.focus2};
    font-family: ${({ theme }) => theme.font.family.focus2};
    line-height: ${({ theme }) => theme.font.lineheight.focus2};
    border-radius: 8px;
    background-color: ${({ theme }) => theme.color.main};
    color: ${({ theme }) => theme.color.white};
    margin: 42px 28px 0;
    padding: 8px 16px;
    pointer-events: auto;

    &:active {
      cursor: pointer;
      background-color: ${({ theme }) => theme.color.sub};
    }
  `,
};
